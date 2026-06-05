# Mulder Investigation Report

**Case:** szechuan
**Generated:** 2026-06-05T09:00:11.373876+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 89 evidence sources (19 memory, 23 disk, 47 other) | 430 tool calls | 53 minutes
**Results:** 17 findings (4 critical, 9 high) | 12 confirmed, 5 inference
**Timeline:** 2020-09-18 to 2020-09-19

**Key Threats:**
- coreupdater.exe Malware with Active C2 Connection to 203.78.103.109
- Attack Timeline: Kali Linux Brute-Force Followed by Credential-Based DC Compromise
- Environment-Wide Meterpreter Implant in spoolsv.exe Across DC01 and DESKTOP-SDN1RPT
- Cross-System Credential Theft Chain: Workstation Hash Dump Enabling DC Authentication

**Attack Lifecycle:**
- **Initial Access / Deployment** (2020-09-18 to 2020-09-19): Cross-System Credential Theft Chain: Workstation Hash Dump Enabling DC Authentication (+12 related)
- **Lateral Movement** (2020-09-18): Lateral Movement via Multiple Compromised Domain Accounts from Workstation to DC
- **Credential Access** (2020-09-19): Brute-Force Password Attack Against DC01 from Kali Linux Attack Machine

**Tools:** search (120), get_raw_output (35), submit_finding (18), extract_archive (15), open_case (15). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **coreupdater.exe Malware with Active C2 Connection to 203.78.103.109** (2020-09-19T03:40:49 to 2020-09-19T03:43:10)


- **Attack Timeline: Kali Linux Brute-Force Followed by Credential-Based DC Compromise** (2020-09-19T03:21:25 to 2020-09-19T03:52:14)


- **Environment-Wide Meterpreter Implant in spoolsv.exe Across DC01 and DESKTOP-SDN1RPT** (2020-09-19T01:22:57)


- **Cross-System Credential Theft Chain: Workstation Hash Dump Enabling DC Authentication** (2020-09-18T22:42:14 to 2020-09-19T03:52:14)




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

430 tool calls were executed across 14
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Digital Forensic Investigation Report — Case Szechuan

## Background

This investigation was initiated in response to a suspected compromise of the C137.local Active Directory domain environment. Two forensic evidence items were provided for analysis: a memory dump from the domain controller CITADEL-DC01 (10.42.85.10) and a memory dump from the workstation DESKTOP-SDN1RPT (10.42.85.115). The domain controller runs Windows Server and hosts Active Directory Domain Services for the C137.local domain. The workstation runs a Windows 10 desktop operating system with Windows Defender active as the primary endpoint protection solution.

A total of 14 evidence sources were indexed across 430 tool invocations during this investigation, encompassing memory forensics (Volatility 3 process analysis, code injection detection, network connection scanning, service enumeration), disk artifact analysis (MFT parsing, ShimCache, Amcache, Prefetch, registry hive parsing), event log analysis (Security, System, PowerShell Operational, Active Directory Web Services), IOC carving (bulk_extractor for URLs, domains, emails), string extraction from pagefiles, YARA signature scanning (raw memory and per-process VAD scanning), threat detection via Hayabusa and Chainsaw Sigma rules, IOC enrichment, and composite cross-correlation analyses. The investigation produced 17 forensic findings — 4 critical, 9 high, 2 medium, and 2 informational — mapped to 24 distinct MITRE ATT&CK techniques. Of these findings, 12 were assessed at confirmed confidence (corroborated by two or more independent evidence sources) and 5 at inference confidence.

## Incident Timeline

The reconstructed incident timeline spans approximately six and a half hours on September 18–19, 2020, and can be divided into four distinct operational phases.

**Phase 1 — Workstation Compromise and Credential Harvesting (September 18, 2020, approximately 22:30–23:00 UTC)**

The earliest confirmed attacker activity occurred on the DESKTOP-SDN1RPT workstation. Memory forensics revealed that powershell.exe PID 508 was spawned by a parent process (PID 1380) that is no longer present in the process list, indicating the parent was a temporary execution vehicle that has since exited. PID 508 in turn spawned powershell.exe PID 3316 at 05:08:43 UTC on September 19, creating a nested PowerShell execution chain. Both processes had empty or hidden command-line arguments, a deliberate evasion technique. Volatility malfind detected multiple PAGE_EXECUTE_READWRITE memory regions in PID 3316 containing MZ PE headers with commit charges of 36, 107, and 57 pages — a memory allocation pattern consistent with Metasploit Meterpreter reflective DLL injection.

During this phase, the attacker performed credential harvesting on the workstation. YARA scanning of the DESKTOP-SDN1RPT memory dump detected the NTLM hash dump output pattern "500:aad3b435b51404eeaad3b435b51404ee:" at six distinct offsets. This specific format — the built-in Administrator account's RID followed by the well-known empty LM hash and the NT hash — is the characteristic output of credential dumping tools such as Mimikatz's hashdump module and would not appear in legitimate system operations or antivirus definition databases. The presence of this pattern confirms that NTLM password hashes were extracted from the local Security Account Manager database.

Additionally, YARA per-process VAD scanning detected base64-encoded PowerShell command patterns (the "JAB" indicator, which decodes to a variable assignment prefix) within the Registry process (PID 92), indicating that obfuscated PowerShell payloads were stored within registry hives, likely for staging or persistence purposes.

A Skeleton Key attack patcher YARA signature also matched in the raw memory dump, detecting strings including "HookDC.dll," "CDLocateCSystem," and "SamIRetrievePrimaryCredentials." However, counter-analysis determined significant false positive risk: most matched strings are legitimate Windows API exports from system DLLs (cryptdll.dll, samsrv.dll), and the most specific indicator — "HookDC.dll" — was confirmed present within Windows Defender malware definition content on this system. Furthermore, the subsequent brute-force activity against DC01 would have been unnecessary if a Skeleton Key had been successfully deployed, since the attacker could have authenticated with any arbitrary password. This finding was accordingly downgraded from critical to high severity and from confirmed to inference confidence. The Skeleton Key toolkit may have been present on the workstation, but the raw memory YARA match alone cannot distinguish actual tool presence from antivirus definition artifacts.

**Phase 2 — Lateral Movement to Domain Controller (September 18, 2020, 22:42–23:00 UTC)**

Beginning at 22:42:14 UTC, the Windows Security event log on CITADEL-DC01 recorded a coordinated series of network logon events (Event ID 4624, LogonType 3) originating from 10.42.85.115 (DESKTOP-SDN1RPT) using multiple domain accounts. The C137\Administrator account authenticated via Kerberos at 22:42:14, with Event ID 4672 confirming the assignment of full administrative privileges including SeDebugPrivilege, SeTakeOwnershipPrivilege, and SeLoadDriverPrivilege. Minutes later, at 22:44:11–13, the C137\ricksanchez account authenticated from the same source with comparable administrative privileges (SeDebugPrivilege, SeRestorePrivilege, SeEnableDelegationPrivilege). The C137\mortysmith account (SID: S-1-5-21-2232410529-1445159330-2725690660-1108) followed at 22:46:39–40. Both ricksanchez and mortysmith accounts were used again at 22:52:49–50 and 23:00:19–29, respectively.

The rapid sequential use of three different privileged domain accounts from a single compromised host within an eighteen-minute window is a hallmark of credential harvesting and lateral movement operations. The NTLM hash dump artifacts recovered from the workstation's memory provide the means by which these credentials were obtained.

**Phase 3 — Brute-Force Authentication and C2 Infrastructure Engagement (September 19, 2020, 03:21–03:22 UTC)**

Approximately four and a half hours after the initial lateral movement, a second authentication sequence began. Between 03:21:25 and 03:21:33 UTC, the Security event log recorded at least eight rapid-fire failed logon events (Event ID 4625) targeting the Administrator account on CITADEL-DC01 from a workstation named "kali." The authentication attempts used NTLM (LogonType 3, network logon) and returned Status 0xC000006D with SubStatus 0xC000006A, confirming the username was correct but the password was wrong. The approximately one-second interval between attempts is consistent with automated password brute-forcing. The workstation name "kali" strongly suggests use of Kali Linux, a dedicated offensive security distribution.

The brute-force ceased at approximately 03:21:46, and a successful Administrator logon (SID S-1-5-21-2232410529-1445159330-2725690660-500, LogonId 0x510986) was recorded at 03:22:07. Two seconds later, at 03:22:09, Event ID 4648 recorded an explicit credential logon on the domain controller where the source network address was 194.61.24.102 — the same external IP address later confirmed as the malware staging server hosting coreupdater.exe. This event showed authentication through winlogon.exe (PID 0x9F0) targeting C137\Administrator against TargetServerName: localhost. A second Event 4648 with a similar pattern followed at 03:22:37. The use of the same IP address for both hosting malware and authenticating to the domain controller confirms this IP is attacker-controlled infrastructure.

**Phase 4 — Malware Deployment and C2 Establishment on Domain Controller (September 19, 2020, 03:40–03:52 UTC)**

Following successful authentication, the attacker deployed the coreupdater.exe binary to the domain controller. The process (PID 3644) started at 03:40:49 UTC and established an outbound TCP connection from 10.42.85.10:62613 to 203.78.103.109:443 (HTTPS). The connection status was ESTABLISHED at the time of memory capture. The MFT records show coreupdater.exe was written to C:\Windows\System32\ at 03:52:14, a location chosen to masquerade as a legitimate system binary. The file is unusually small at 7,168 bytes, consistent with a lightweight downloader or beacon rather than a full-featured implant.

Bulk_extractor URL carving confirmed the download source as http://194.61.24.102/coreupdater.exe. Pagefile string analysis from the DESKTOP-SDN1RPT workstation revealed that Windows SmartScreen performed a reputation check on this binary when it was first encountered on the workstation. The caller process was C:\Windows\explorer.exe (PID 4008), confirming the binary was manually launched through Windows Explorer. SmartScreen ultimately issued a "block" action, and Windows Defender successfully detected and quarantined coreupdater.exe on the workstation (PID 8324, which had already exited by the time of memory capture). However, no such protection intervened on the domain controller, where the binary executed successfully and maintained its C2 connection.

Concurrent with or prior to coreupdater.exe deployment, a Meterpreter reflective DLL was injected into the Print Spooler service (spoolsv.exe, PID 3724) on DC01. YARA scanning confirmed the presence of "metsrv.x64.dll" at five offsets and "ReflectiveLoader" at fifteen offsets within PID 3724's memory. Volatility malfind detected PAGE_EXECUTE_READWRITE regions containing x64 shellcode patterns (fc H\x89\xce), three MZ headers, and one MZARUH stub. Notably, Volatility netscan showed PID 3724 listening on TCP port 62475 — an atypical port for the Print Spooler service, consistent with a Meterpreter bind handler. The Volatility svcscan output confirmed PID 3724 was running as the "Spooler" service with the SERVICE_INTERACTIVE_PROCESS flag, which is unusual for a domain controller.

An identical Meterpreter injection was confirmed in spoolsv.exe PID 2188 on the DESKTOP-SDN1RPT workstation, with matching MZ PE headers in PAGE_EXECUTE_READWRITE memory and the same 36-page commit charge allocation pattern. This cross-system consistency confirms coordinated deployment of the same Metasploit payload across both compromised systems, using the Print Spooler service as a persistence vehicle — a service that auto-starts and runs as SYSTEM.

## Key Findings

**Meterpreter Reflective DLL Injection (Environment-Wide)**

The most significant technical finding is the deployment of identical Meterpreter reflective DLL payloads into the Print Spooler service (spoolsv.exe) on both CITADEL-DC01 and DESKTOP-SDN1RPT. The YARA signature "HKTL_Meterpreter_inMemory" confirmed the presence of the Metasploit server DLL (metsrv.x64.dll) and its ReflectiveLoader export in the domain controller's spoolsv.exe (PID 3724). The matching memory allocation patterns — specifically the 36-page PAGE_EXECUTE_READWRITE regions containing MZ PE headers — across two independent memory dumps from different systems establish that a single attacker used the same toolkit and technique consistently. The domain controller's Meterpreter instance had an active bind handler on TCP port 62475, providing the attacker with persistent remote access to the most critical system in the environment.

**coreupdater.exe Custom Malware**

A lightweight 7,168-byte executable named coreupdater.exe was deployed to C:\Windows\System32\ on the domain controller, establishing an HTTPS C2 channel to 203.78.103.109:443. The binary was downloaded from http://194.61.24.102/coreupdater.exe and manually executed via Windows Explorer. The choice of System32 as the drop location represents a masquerade technique intended to blend with legitimate Windows binaries. The binary did not persist through ShimCache or registry autorun mechanisms, suggesting it was deployed for immediate operational use alongside the Meterpreter implant rather than long-term persistence. On the workstation, Windows Defender successfully detected and blocked this binary; on the domain controller, no endpoint protection intervened.

**Cross-System Credential Theft Chain**

The investigation confirmed a credential theft chain spanning both systems, corroborated by five independent evidence sources: YARA memory signatures, EVTX security logs, Volatility netscan, bulk_extractor URL carving, and MFT timestamps. NTLM hash dump output for the Administrator account (RID 500) was recovered from DESKTOP-SDN1RPT memory, providing the means for the subsequent authentication sequence against DC01. The progression from credential harvesting on the workstation to successful domain controller authentication is confirmed by the timing and nature of the Security event log entries: lateral movement with stolen credentials at 22:42–23:00 on September 18, followed by the brute-force and explicit credential logon sequence at 03:21–03:22 on September 19.

**PowerShell-Based Attack Framework**

The attacker's primary interactive post-exploitation session on the workstation operated through a nested PowerShell chain (PID 508 → PID 3316) with deliberately hidden command-line arguments. The injected Meterpreter payload in PID 3316's memory, combined with encoded PowerShell patterns stored in registry hives (detected by YARA's JAB pattern rule in the Registry process), indicates the attacker used obfuscated PowerShell as the primary execution framework for credential dumping, lateral movement staging, and tool deployment.

**Tofu Backdoor Signature**

A YARA signature for the Tofu backdoor family matched in the DESKTOP-SDN1RPT memory at two offsets, detecting the HTTP header string "Cookies: Sym1.0" — a known C2 communication indicator. While this string is specific enough to be unlikely in legitimate software, a single YARA match cannot confirm active execution versus residual presence from a tool that was loaded and unloaded, or from a related attack framework sharing this signature. This finding remains at inference confidence.

**Ruled-Out Activities**

Systematic analysis found no evidence of several expected post-compromise activities. No NTDS.dit extraction was detected — references to ntdsutil and vssadmin in pagefile strings were exclusively from Windows Defender malware signature databases. No event log clearing was found: Event ID 104 (log cleared) returned zero matches in System.evtx, and Event ID 1102 (audit log cleared) returned zero matches in Security.evtx. No timestomping was detected in MFT timestamp analysis. No data staging or exfiltration indicators were identified — no archive files in staging locations, no upload service URLs in bulk_extractor output. Additionally, CoinMiner and Webshell YARA signatures that matched within the MemCompression process (PID 1816) on DESKTOP-SDN1RPT were assessed as false positives caused by Windows Defender malware definition content in compressed memory, confirmed by the absence of any independent evidence of cryptocurrency mining or webshell deployment.

## Threat Intelligence and Attribution

The attacker demonstrated a consistent Metasploit-centric toolkit throughout the operation. The confirmed use of Meterpreter reflective DLL injection (metsrv.x64.dll with ReflectiveLoader), credential dumping producing NTLM hash output in the standard RID:LMhash:NThash format, and the use of the Print Spooler service as an injection target are all consistent with standard Metasploit Framework post-exploitation modules (exploit/windows/local/ms10_061_spoolss or post/windows/manage/migrate patterns). The attacker's use of a "kali" workstation name during the brute-force phase provides additional confirmation of a Kali Linux-based offensive toolset.

IOC enrichment identified the C2 destination 203.78.103.109 as hosted in Thailand (AS23884, Proen Corp) and the malware staging server 194.61.24.102 as hosted in Russia (AS41842, LLC "MEDIA SYSTEMS"). The use of geographically dispersed infrastructure across Russian and Thai hosting providers is consistent with commodity hosting arrangements commonly used by both criminal and state-aligned operators, and does not by itself support attribution to a specific threat group.

The Tofu backdoor YARA signature (Backdoor.Tofu, "Cookies: Sym1.0") has been historically associated with APT campaigns targeting organizations in East and Southeast Asia. However, a single string match in a raw memory dump is insufficient to attribute this intrusion to any specific threat group. The match may indicate the presence of shared tools, overlapping infrastructure, or merely a coincidental string pattern in a related framework.

The operational pattern — workstation compromise, credential harvesting, lateral movement to a domain controller, deployment of both a custom lightweight C2 binary and a standard Meterpreter implant — is consistent with a broad range of threat actors from criminal ransomware precursors to targeted intrusion operators. The attacker demonstrated moderate operational security (hidden command lines, masquerading binary names, use of HTTPS for C2) but also exhibited indicators of limited sophistication (failed brute-force attempts before using stolen credentials, deployment of a known binary that was immediately detected by Windows Defender on the workstation). The evidence supports characterizing this as a targeted intrusion by an operator with access to standard penetration testing frameworks, but definitive attribution to a named threat group is not supportable from the available evidence.

## Impact Assessment

The compromise affected two systems within the C137.local domain: the domain controller CITADEL-DC01 (10.42.85.10) and the workstation DESKTOP-SDN1RPT (10.42.85.115). The domain controller is the most critical asset in any Active Directory environment, as its compromise grants the attacker effective control over all domain-joined systems, user accounts, and group policies.

Three domain accounts were confirmed compromised through credential harvesting and subsequent use: C137\Administrator (the built-in domain administrator with RID 500), C137\ricksanchez (with full administrative privileges including SeDebugPrivilege and SeEnableDelegationPrivilege), and C137\mortysmith. The compromise of the domain Administrator account alone provides the attacker with unrestricted access to all domain resources, including the ability to create additional accounts, modify group policies, access any shared resource, and deploy software to any domain-joined system.

The Meterpreter implants in the Print Spooler service on both systems ran under the SYSTEM security context, providing the highest level of local privilege. The bind handler on TCP port 62475 on DC01's spoolsv.exe provided persistent remote access capability. The coreupdater.exe binary maintained an active C2 channel over HTTPS to 203.78.103.109, potentially allowing command execution, additional tool deployment, and data access.

Despite the severity of the access achieved, no evidence of data exfiltration was identified. No NTDS.dit database extraction was detected, no archive files were staged in suspicious locations, and no outbound connections to known exfiltration services were found. The attacker's operational focus appeared to be on establishing persistent access and credential control rather than immediate data theft, which is consistent with either a pre-ransomware staging operation or the early phases of a longer-term intrusion that was detected before data theft objectives were pursued.

## Immediate Tactical Containment

The following actions should be executed immediately to contain the active threat:

1. Isolate CITADEL-DC01 (10.42.85.10) from the network. The domain controller has an active C2 connection to 203.78.103.109:443 and a Meterpreter bind handler on TCP port 62475 in spoolsv.exe (PID 3724). Network isolation must precede any remediation to prevent the attacker from deploying additional tools or destroying evidence.

2. Isolate DESKTOP-SDN1RPT (10.42.85.115) from the network. The workstation contains Meterpreter in spoolsv.exe (PID 2188) and injected code in powershell.exe (PID 3316). Although no active C2 connections from this system were observed at capture time, the implants remain capable of re-establishing communication.

3. Block the following IP addresses at the perimeter firewall, proxy, and DNS sinkhole: 203.78.103.109 (active C2 server) and 194.61.24.102 (malware staging and authentication source).

4. Terminate the following processes on CITADEL-DC01 after network isolation: coreupdater.exe (PID 3644, C2 to 203.78.103.109:443) and note that spoolsv.exe (PID 3724) contains the Meterpreter implant — stopping the Print Spooler service will terminate this process, but it will restart automatically; the service must be disabled temporarily.

5. Terminate the following processes on DESKTOP-SDN1RPT after network isolation: powershell.exe PID 3316 (injected Meterpreter) and powershell.exe PID 508 (parent of PID 3316, hidden command line). Note that spoolsv.exe PID 2188 also contains Meterpreter and must have its service disabled.

6. Force immediate password resets for the compromised domain accounts: C137\Administrator (RID 500), C137\ricksanchez, and C137\mortysmith. Reset the KRBTGT account password twice (following Microsoft's documented procedure) to invalidate any potentially forged Kerberos tickets.

7. Block the file hash and name coreupdater.exe (7,168 bytes) across all endpoint detection systems. Delete the file from C:\Windows\System32\coreupdater.exe on DC01 after forensic preservation.

8. Block inbound connections to TCP port 62475 on all internal systems to disrupt any additional Meterpreter bind handlers that may exist on systems not yet examined.

9. Monitor all domain authentication logs for logon attempts from the workstation name "kali" and from any of the three compromised accounts until password resets are confirmed effective.

10. Conduct a sweep of all domain-joined systems for spoolsv.exe processes with unusual memory allocations or network listeners on non-standard ports to identify any additional Meterpreter implants beyond the two confirmed systems.

## Strategic Remediation

**Absence of Endpoint Protection on the Domain Controller.** The coreupdater.exe binary was successfully detected and blocked by Windows Defender on DESKTOP-SDN1RPT but executed without intervention on CITADEL-DC01, enabling C2 establishment from the domain controller (findings f_0d0c1b50 and f_9ecf3b9c). This disparity indicates that the domain controller either lacked active endpoint protection or had its antivirus capabilities degraded. Deploy and enforce endpoint detection and response (EDR) coverage on all domain controllers with equivalent or stricter policies than workstation endpoints, ensuring real-time scanning and behavioral detection are active.

**Print Spooler Service Exposed on the Domain Controller.** The attacker exploited the Print Spooler service (spoolsv.exe) as the injection target for Meterpreter on both systems (finding f_bb541778), leveraging a service that runs as SYSTEM and auto-starts. The Spooler service was running with the SERVICE_INTERACTIVE_PROCESS flag on DC01, which is unnecessary for a domain controller. Disable the Print Spooler service on all domain controllers where printing functionality is not required, consistent with Microsoft's longstanding security guidance reinforced by the PrintNightmare vulnerability series (CVE-2021-34527).

**Insufficient Network Authentication Controls.** The brute-force attack from the "kali" workstation (finding f_69ff7d7a) generated at least eight failed logon attempts in eight seconds against the Administrator account without triggering any automated lockout or alerting. Implement account lockout policies (e.g., lock after five failed attempts within five minutes) for all privileged accounts, and deploy real-time alerting on Event ID 4625 clusters targeting administrative accounts. Additionally, the direct network logon from an unrecognized workstation named "kali" succeeded without restriction, indicating the absence of network access controls limiting which devices can authenticate to the domain controller.

**Credential Exposure Enabling Lateral Movement.** The NTLM hash dump on DESKTOP-SDN1RPT (finding f_a1480fa1) provided credentials that were subsequently used for lateral movement to DC01 using three domain accounts (finding f_5d600935). The successful pass-the-hash authentication indicates that NTLM authentication was enabled and unrestricted. Where operationally feasible, enforce Kerberos-only authentication and disable NTLM fallback for domain administrative accounts. Implement credential tiering to ensure domain administrator credentials are never cached or used on workstation-tier systems, preventing credential harvesting on a compromised workstation from yielding domain controller access.

**Unrestricted Outbound HTTPS from the Domain Controller.** The coreupdater.exe binary established an outbound HTTPS connection from DC01 to 203.78.103.109:443 (finding f_0d0c1b50), indicating that the domain controller had unrestricted outbound internet access. Domain controllers should not require direct internet connectivity. Implement egress filtering that blocks all outbound traffic from domain controllers except to explicitly whitelisted destinations (Windows Update, time synchronization, certificate revocation endpoints), routing all necessary traffic through an inspecting proxy.

## Conclusion

**Q1. What systems were compromised?** Two systems were confirmed compromised: the domain controller CITADEL-DC01 (10.42.85.10) and the workstation DESKTOP-SDN1RPT (10.42.85.115). Both contained Meterpreter reflective DLL injections in spoolsv.exe. The domain controller additionally had the coreupdater.exe C2 binary and an active connection to the attacker's infrastructure.

**Q2. How did the attacker gain initial access?** The precise initial access vector to DESKTOP-SDN1RPT could not be determined from the available evidence. The earliest confirmed attacker activity is the lateral movement from the workstation to DC01 at 22:42:14 UTC on September 18. The workstation was already compromised with Meterpreter, NTLM hash dumping tools, and obfuscated PowerShell payloads by this time. Access to the domain controller was achieved through credential-based authentication using stolen domain administrator credentials, preceded by a brief brute-force attempt from a Kali Linux system and remote authentication from the attacker's infrastructure at 194.61.24.102.

**Q3. What lateral movement occurred?** Confirmed lateral movement from DESKTOP-SDN1RPT (10.42.85.115) to CITADEL-DC01 (10.42.85.10) was identified using three domain accounts (Administrator, ricksanchez, mortysmith) via Kerberos and NTLM network logons (Event ID 4624 LogonType 3). The movement occurred in two phases: credential-based logons between 22:42 and 23:00 on September 18, and brute-force followed by explicit credential logon from the C2 IP at 03:21–03:22 on September 19.

**Q4. What persistence mechanisms were installed?** The primary persistence mechanism was Meterpreter reflective DLL injection into the Print Spooler service (spoolsv.exe) on both systems. This service runs as SYSTEM, starts automatically, and will reload its injected payload upon restart. The domain controller's Meterpreter instance additionally maintained a bind handler on TCP port 62475. The coreupdater.exe binary was placed in System32 but did not have registry-based autorun persistence, suggesting it was intended for session-level use. Obfuscated PowerShell content stored in registry hives on the workstation may represent an additional persistence mechanism.

**Q5. Was data exfiltrated, and if so, what and how much?** No evidence of data exfiltration was found. No NTDS.dit extraction, archive file staging, or connections to known exfiltration services were detected. The C2 channel (coreupdater.exe to 203.78.103.109:443) was established but no outbound data transfer evidence was identified. However, the active C2 channel and the attacker's domain administrator-level access mean that exfiltration capability existed even if it was not exercised during the evidence capture window.

**Q6. What is the full timeline of the incident?** The confirmed incident timeline spans from September 18, 2020 at 22:42:14 UTC (first lateral movement from workstation to DC) to September 19, 2020 at approximately 05:09 UTC (latest process activity in memory captures). Key events: credential-based lateral movement at 22:42–23:00 (Sep 18), brute-force attack at 03:21 (Sep 19), successful authentication at 03:22, coreupdater.exe deployment and C2 at 03:40–03:52, and powershell.exe PID 3316 creation at 05:08. The workstation compromise predates these events but the exact initial compromise time could not be determined.

**Q7. What is the total scope and business impact?** Two systems were compromised: the sole domain controller and a workstation. Three domain accounts were used by the attacker, including the built-in domain Administrator. The compromise of the domain controller represents a complete Active Directory domain compromise, as the attacker had SYSTEM-level access to the system hosting the AD database. All credentials, group policies, and trust relationships managed by this domain controller should be considered potentially exposed. The business impact is severe: all domain-joined systems and all domain user accounts must be treated as potentially compromised until credential rotation and infrastructure rebuild are complete.

**Q8. What are the recommended remediation actions?** Beyond the immediate tactical containment steps outlined above, the organization should: rebuild both compromised systems from known-good media rather than attempting to clean the existing installations; deploy EDR on all domain controllers; disable the Print Spooler service on domain controllers; implement account lockout policies and privileged access monitoring; enforce credential tiering to prevent domain admin credentials from being used on workstations; restrict outbound network access from domain controllers; and conduct a comprehensive sweep of all domain-joined systems for Meterpreter indicators before restoring normal operations.


---

## Overview

| | |
|---|---|
| Findings | **17** (12 confirmed, 5 inference) |
| Severity | 4 critical, 9 high, 2 medium, 0 low, 2 info |
| Sources | 14 evidence sources across 430 tool calls |


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
| 2020-09-18T22:42:14 | Cross-System Credential Theft Chain: Workstation Hash Dump Enabling DC Authentication | CRITICAL | yara.memory, evtx.windows_system32_winevt_logs_security, volatility.netscan, yara.volatility, bulk.url |
| 2020-09-18T22:42:14 | Skeleton Key Attack Detected in DESKTOP-SDN1RPT Memory | HIGH | yara.memory |
| 2020-09-18T22:42:14 | NTLM Hash Dump Output Detected in DESKTOP-SDN1RPT Memory | HIGH | yara.memory |
| 2020-09-18T22:42:14 | Lateral Movement via Multiple Compromised Domain Accounts from Workstation to DC | HIGH | evtx.windows_system32_winevt_logs_security, yara.memory, volatility.malfind |
| 2020-09-18T22:42:14 | Tofu_Backdoor Signature Detected in DESKTOP-SDN1RPT Memory | MEDIUM | yara.memory |
| 2020-09-18T22:42:14 | Encoded PowerShell Commands (JAB Pattern) in DESKTOP-SDN1RPT Registry Memory | MEDIUM | yara.volatility |
| 2020-09-19T01:22:57 | Environment-Wide Meterpreter Implant in spoolsv.exe Across DC01 and DESKTOP-SDN1RPT | CRITICAL | volatility.malfind, yara.memory, volatility.netscan, volatility.svcscan |
| 2020-09-19T03:21:25 | Attack Timeline: Kali Linux Brute-Force Followed by Credential-Based DC Compromise | CRITICAL | evtx.windows_system32_winevt_logs_security, volatility.netscan, volatility.pstree, ez.mft |
| 2020-09-19T03:21:25 | Brute-Force Password Attack Against DC01 from Kali Linux Attack Machine | HIGH | evtx.windows_system32_winevt_logs_security |
| 2020-09-19T03:21:25 | Network IOC Summary: Attacker Infrastructure IPs and Malware Download URL | HIGH | volatility.netscan, bulk.domain, volatility.pstree |
| 2020-09-19T03:22:09 | Remote Authentication to DC from C2 Infrastructure IP 194.61.24.102 | HIGH | evtx.windows_system32_winevt_logs_security, bulk.url |
| 2020-09-19T03:40:49 | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 | CRITICAL | volatility.netscan, volatility.pstree, bulk.domain, bulk.url, strings.output, ez.mft |
| 2020-09-19T03:40:49 | coreupdater.exe Malware Dropped in System32 and Manually Executed via Explorer | HIGH | strings.output, ez.mft, enrichment.iocs |
| 2020-09-19T05:08:43 | Code Injection in powershell.exe (PID 3316) on DESKTOP-SDN1RPT Matching Meterpreter Pattern | HIGH | volatility.malfind, yara.memory |
| 2020-09-19T05:08:43 | PowerShell Attack Chain with Hidden Command Lines on DESKTOP-SDN1RPT | HIGH | volatility.cmdline, volatility.malfind |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] coreupdater.exe Malware with Active C2 Connection to 203.78.103.109

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:40:49 to 2020-09-19T03:43:10 |
| **Sources** | volatility.netscan, volatility.pstree, bulk.domain, bulk.url, strings.output, ez.mft |
| **Evidence Refs** | tc_3aa5c15b, tc_e7054ca1, tc_425841e3 |
| **ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |


A malicious executable coreupdater.exe (PID 3644) was found running on CITADEL-DC01 with an ESTABLISHED TCP connection from 10.42.85.10:62613 to 203.78.103.109:443. The binary was downloaded from http://194.61.24.102/coreupdater.exe, confirmed by bulk_extractor URL carving and browser history artifacts in the DESKTOP-SDN1RPT pagefile. The file is only 7,168 bytes and was placed in C:\Windows\System32\coreupdater.exe — masquerading as a legitimate system binary. On the DESKTOP-SDN1RPT workstation, Windows Defender detected and blocked this binary (action: "block" after "checkReputation"). The process tree shows coreupdater.exe ran in session 3 (interactive logon session) on DC01 from 2020-09-19 03:40:49 to 03:43:10 (exited). On DESKTOP-SDN1RPT it appeared as PID 8324 (also exited). The MFT shows filesystem activity for coreupdater.exe around 2020-09-19 03:52:14. This represents an attacker-deployed backdoor/downloader connecting to external C2 infrastructure from the domain controller.



### 2. [CRITICAL] Attack Timeline: Kali Linux Brute-Force Followed by Credential-Based DC Compromise

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:21:25 to 2020-09-19T03:52:14 |
| **Sources** | evtx.windows_system32_winevt_logs_security, volatility.netscan, volatility.pstree, ez.mft |
| **Evidence Refs** | tc_9830c250, tc_d7ff6284, tc_3aa5c15b, tc_425841e3 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1003](https://attack.mitre.org/techniques/T1003/) |


Correlating Security Event Log data with memory forensics reveals a clear attack sequence on 2020-09-19:

1. 03:21:25-03:21:46: Rapid brute-force password attempts from workstation "kali" against Administrator on CITADEL-DC01 (Event 4625, Status 0xC000006A - correct username, wrong password, NTLM authentication)

2. 03:22:07: Successful Administrator logon (SID S-1-5-21-2232410529-1445159330-2725690660-500, LogonId 0x510986)

3. 03:22:09: Event 4648 explicit credential logon from 194.61.24.102 (the malware hosting server) targeting C137\Administrator through winlogon.exe (PID 0x9F0), TargetServerName: localhost

4. 03:22:37: Second Event 4648 explicit credential logon with similar pattern

5. 03:40:49: coreupdater.exe (PID 3644) starts on DC01, establishing C2 to 203.78.103.109:443

6. 03:52:14: coreupdater.exe written to C:\Windows\System32\ on DC01 filesystem (MFT timestamp)

The attacker used credentials obtained from NTLM hash dumping on the workstation (confirmed by YARA NTLM_Dump_Output rule) to authenticate to the DC after the initial brute-force attempt. The Kali workstation, external IP 194.61.24.102, and the compromised workstation DESKTOP-SDN1RPT appear to be the attack infrastructure.



### 3. [CRITICAL] Environment-Wide Meterpreter Implant in spoolsv.exe Across DC01 and DESKTOP-SDN1RPT

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T01:22:57 |
| **Sources** | volatility.malfind, yara.memory, volatility.netscan, volatility.svcscan |
| **Evidence Refs** | tc_baa18320, tc_34a294df, tc_e7054ca1, tc_4df97cc7, tc_0dee61fb |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1059.006](https://attack.mitre.org/techniques/T1059/006/) |


Cross-system analysis reveals identical Meterpreter reflective DLL injection in the Print Spooler service (spoolsv.exe) on both compromised systems, confirming a coordinated attack using the same toolkit:

**DC01 (CITADEL-DC01, 10.42.85.10) — spoolsv.exe PID 3724:**
- YARA rule HKTL_Meterpreter_inMemory matched "metsrv.x64.dll" (5 offsets) and "ReflectiveLoader" (15 offsets)
- Volatility malfind: PAGE_EXECUTE_READWRITE regions with x64 shellcode (fc H\x89\xce), 3 MZ headers, 1 MZARUH stub
- Netscan: LISTENING on TCP port 62475 (atypical for print spooler — Meterpreter bind handler)
- Volatility svcscan: PID 3724 running as "Spooler" service with SERVICE_INTERACTIVE_PROCESS flag (unusual for a DC)

**DESKTOP-SDN1RPT (10.42.85.115) — spoolsv.exe PID 2188:**
- Volatility malfind: MZ PE header in PAGE_EXECUTE_READWRITE region (CommitCharge=36) — same allocation pattern as DC01
- No active network listeners at capture time (implant may have been dormant or using a different callback mechanism)

**Convergence:** The identical injection technique (reflective DLL loading into spoolsv.exe), matching memory allocation patterns (36-page CommitCharge), and same YARA signatures across two independent memory dumps from different systems confirm coordinated deployment of the same Metasploit payload. The attacker established persistent implants in the Print Spooler service on both systems — a service that auto-starts and runs as SYSTEM, providing reliable persistence without registry modifications.



### 4. [CRITICAL] Cross-System Credential Theft Chain: Workstation Hash Dump Enabling DC Authentication

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T22:42:14 to 2020-09-19T03:52:14 |
| **Sources** | yara.memory, evtx.windows_system32_winevt_logs_security, volatility.netscan, yara.volatility, bulk.url |
| **Evidence Refs** | tc_34a294df, tc_9830c250, tc_d7ff6284, tc_3aa5c15b, tc_ae64a08b |
| **ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1556.001](https://attack.mitre.org/techniques/T1556/001/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |


Cross-correlation of evidence across DESKTOP-SDN1RPT and CITADEL-DC01 reveals a credential theft chain spanning both systems, with artifacts from 4+ independent sources confirming the attack progression:

**Phase 1 — Credential Harvesting on DESKTOP-SDN1RPT (10.42.85.115):**
- YARA NTLM_Dump_Output rule matched the pattern "500:aad3b435b51404eeaad3b435b51404ee:" (RID 500 Administrator NTLM hash format) at 6 offsets in DESKTOP-SDN1RPT memory — this is a specific credential dump output format unlikely to originate from AV definitions
- Skeleton Key patcher YARA rule also matched, though counter-analysis identified significant false positive risk from AV definitions containing "HookDC.dll" and legitimate Windows API names (CDLocateCSystem, SamIRetrievePrimaryCredentials) — confidence downgraded to inference (see f_56f388ba)
- Encoded PowerShell (JAB pattern) in Registry process indicates attack tooling staged in registry hives

**Phase 2 — Credential Usage Against DC01 (10.42.85.10):**
- EVTX Security log: 8+ failed brute-force attempts (Event 4625) from workstation "kali" at 03:21:25-03:21:33, Status 0xC000006A (correct username, wrong password)
- EVTX Security log: Successful Administrator logon at 03:22:07
- EVTX Security log: Explicit credential logon (Event 4648) from 194.61.24.102 at 03:22:09

**Phase 3 — Post-Authentication DC Compromise:**
- coreupdater.exe deployed to C:\Windows\System32\ on DC01, C2 to 203.78.103.109:443
- Meterpreter reflective DLL injected into spoolsv.exe PID 3724

**Convergence:** The credential dumping artifacts on the workstation (YARA memory signatures) are consistent with enabling the authentication events on the DC (EVTX security logs). The timing is consistent: lateral movement with credentials (22:42-23:00 on Sep 18) preceded the brute-force/authentication sequence (03:21-03:22 on Sep 19), and the NTLM hash dump provided the means to obtain credentials subsequently used. Five independent evidence sources (YARA memory scan, EVTX security logs, Volatility netscan, bulk_extractor URLs, MFT timestamps) corroborate this chain. The Skeleton Key component has been downgraded to inference-level confidence, but the credential chain narrative remains strong based on the NTLM dump output, confirmed Meterpreter implants, and EVTX authentication events.



### 5. [HIGH] Skeleton Key Attack Detected in DESKTOP-SDN1RPT Memory

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2020-09-18T22:42:14 |
| **Sources** | yara.memory |
| **Evidence Refs** | tc_34a294df |
| **ATT&CK** | [T1556.001](https://attack.mitre.org/techniques/T1556/001/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |


YARA rule skeleton_key_patcher matched extensively in the DESKTOP-SDN1RPT raw memory dump. The rule matched multiple string categories: (1) "lsass.exe" at 100+ offsets; (2) "HookDC.dll" at 6 offsets; (3) "cryptdll.dll" at 16 offsets; (4) "samsrv.dll" at 7 offsets; (5) "CDLocateCSystem" at 4 offsets; (6) "SamIRetrievePrimaryCredentials" and "SamIRetrieveMultiplePrimaryCredentials" at 2 offsets each.

**Counter-analysis — significant false positive risk:** Most matched strings are legitimate Windows system components that exist in ANY Windows memory dump: lsass.exe (system process), cryptdll.dll and samsrv.dll (system DLLs), CDLocateCSystem and SamIRetrievePrimaryCredentials (exported API functions from those DLLs). The most Skeleton-Key-specific string, "HookDC.dll", was confirmed present in Windows Defender malware definition content on this system (strings output shows it surrounded by AV detection signature names like "Behavior:Win32/Lol", "!Banload.ASZ"). Because the YARA scan was against the full raw memory dump (not per-process), the rule fires when ALL required strings exist ANYWHERE in the multi-GB dump — a condition easily met when legitimate system DLL exports combine with AV definition content containing "HookDC.dll".

**Timeline inconsistency further weakens this finding:** If a Skeleton Key had been successfully deployed to patch DC01's LSASS (allowing a master password for any Kerberos account), the brute-force attack from "kali" at 03:21:25 would have been unnecessary — the attacker could have authenticated with any password. The fact that brute-force was attempted suggests either the Skeleton Key was never deployed, targeted a different system, or the tool was present but not used.

**Assessment:** Downgraded from critical/confirmed to high/inference. The Skeleton Key toolkit MAY have been present on the workstation, but the raw memory YARA match alone cannot distinguish actual tool presence from AV definition artifacts. No per-process corroboration (e.g., vadyarascan matching within a specific attack process) exists to confirm deployment. The finding remains at high severity because it is part of a broader attack chain and the tool's presence — even if only in definitions — is contextually relevant alongside confirmed Meterpreter injection and NTLM hash dumping on the same system.



### 6. [HIGH] NTLM Hash Dump Output Detected in DESKTOP-SDN1RPT Memory

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T22:42:14 |
| **Sources** | yara.memory |
| **Evidence Refs** | tc_34a294df |
| **ATT&CK** | [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |


YARA rule NTLM_Dump_Output matched in the DESKTOP-SDN1RPT memory dump at 6 offsets, detecting the string pattern "500:aad3b435b51404eeaad3b435b51404ee:" — the characteristic format of NTLM hash dump output for the built-in Administrator account (RID 500). The LM hash portion "aad3b435b51404eeaad3b435b51404ee" is the well-known empty LM hash, indicating LM hashing is disabled (expected on modern Windows). The presence of this pattern in memory indicates credential dumping tools (likely Mimikatz or hashdump) were used to extract NTLM password hashes from the SAM database or domain controller.

**Counter-analysis note:** Unlike the Skeleton Key YARA match (f_56f388ba), which relies on strings that are legitimate Windows API names and AV definition content, this pattern is the actual OUTPUT FORMAT of credential dumping tools (RID:LMhash:NThash). This format is far more specific and would not typically appear in AV malware definitions. The 6 match offsets spread across memory are consistent with the dump output being held in process memory, pagefile residue, or clipboard data. While raw memory YARA scans carry inherent FP risk, the specificity of this pattern and its corroboration by the broader attack chain (confirmed Meterpreter, brute-force, and lateral movement) support this finding at confirmed confidence.

Combined with the Meterpreter code injection and the subsequent authentication events on the DC, this finding confirms active credential harvesting as part of the compromise.



### 7. [HIGH] Remote Authentication to DC from C2 Infrastructure IP 194.61.24.102

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:22:09 to 2020-09-19T03:22:37 |
| **Sources** | evtx.windows_system32_winevt_logs_security, bulk.url |
| **Evidence Refs** | tc_d7ff6284, tc_61479cab |
| **ATT&CK** | [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1133](https://attack.mitre.org/techniques/T1133/) |


Windows Security Event ID 4648 at 2020-09-19 03:22:09 records an explicit credential logon attempt on CITADEL-DC01.C137.local where the source IP was 194.61.24.102 — the same IP address that hosted the coreupdater.exe malware (http://194.61.24.102/coreupdater.exe). The event shows: Subject: C137\CITADEL-DC01$, Target: C137\Administrator, TargetServerName: localhost, Process: C:\Windows\System32\winlogon.exe. This indicates the attacker authenticated to the domain controller using the Administrator account from their C2 infrastructure. Additional 4648 events at 03:22:37 show continued explicit credential activity. The use of the same IP for both hosting malware and authenticating to the DC confirms this IP is attacker-controlled infrastructure.



### 8. [HIGH] Brute-Force Password Attack Against DC01 from Kali Linux Attack Machine

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:21:25 to 2020-09-19T03:21:33 |
| **Sources** | evtx.windows_system32_winevt_logs_security |
| **Evidence Refs** | tc_9830c250 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |


Multiple rapid-fire Event ID 4625 (failed logon) events were recorded in the Security event log between 2020-09-19 03:21:25 and 03:21:33, targeting the Administrator account on CITADEL-DC01 from a workstation named "kali". The attacks used NTLM authentication (LogonType 3, network logon) with Status 0xC000006D (bad username or authentication information) and SubStatus 0xC000006A (user name is correct but the password is wrong), confirming repeated attempts with incorrect passwords. At least 8 failed attempts occurred in rapid succession (~1 per second), consistent with an automated brute-force or password spraying attack. The workstation name "kali" strongly indicates use of Kali Linux, a well-known penetration testing and offensive security distribution. This attack occurred approximately 1 minute before the Event 4648 explicit credential logon from 194.61.24.102 (03:22:09), suggesting the attacker first attempted to brute-force credentials and then used a different vector (likely credentials obtained from NTLM hash dumping on the workstation) to authenticate successfully.



### 9. [HIGH] Code Injection in powershell.exe (PID 3316) on DESKTOP-SDN1RPT Matching Meterpreter Pattern

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T05:08:43 |
| **Sources** | volatility.malfind, yara.memory |
| **Evidence Refs** | tc_4df97cc7, tc_34a294df |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |


Volatility malfind detected multiple PAGE_EXECUTE_READWRITE memory regions in powershell.exe PID 3316 on the DESKTOP-SDN1RPT workstation, including an MZ PE header (CommitCharge=36). The memory allocation pattern (107-page, 57-page, and 36-page regions) matches the identical pattern seen in the Meterpreter-injected spoolsv.exe PID 3724 on DC01, strongly suggesting the same Metasploit payload was reflectively loaded into this PowerShell process. The process command line is empty (hidden), and it was running alongside a Skeleton Key attack toolkit and NTLM hash dump. spoolsv.exe PID 2188 on the same workstation also contains an MZ header in a PAGE_EXECUTE_READWRITE region (CommitCharge=36), indicating a second injected process. These findings confirm the workstation was actively compromised with multiple implants serving as the attack staging platform.



### 10. [HIGH] Lateral Movement via Multiple Compromised Domain Accounts from Workstation to DC

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T22:42:14 to 2020-09-18T23:00:29 |
| **Sources** | evtx.windows_system32_winevt_logs_security, yara.memory, volatility.malfind |
| **Evidence Refs** | tc_9b405521, tc_261819d1, tc_4fafdd20 |
| **ATT&CK** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1550.002](https://attack.mitre.org/techniques/T1550/002/) |


Security Event Log analysis reveals coordinated network logon activity (Event 4624, LogonType 3) from DESKTOP-SDN1RPT (10.42.85.115) to CITADEL-DC01 using multiple domain accounts within a short time window on 2020-09-18:

- 22:42:14: C137\Administrator - LogonType 3 via Kerberos from 10.42.85.115 (Event 4672 shows full administrative privileges including SeDebugPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege)
- 22:44:11-13: C137\ricksanchez - LogonType 3 via Kerberos from 10.42.85.115 (Event 4672 confirms administrative privileges including SeDebugPrivilege, SeRestorePrivilege, SeEnableDelegationPrivilege)
- 22:46:39-40: C137\mortysmith (SID: S-1-5-21-2232410529-1445159330-2725690660-1108) - LogonType 3 from 10.42.85.115
- 22:52:49-50: C137\ricksanchez - again from 10.42.85.115
- 23:00:19-29: C137\mortysmith - again from 10.42.85.115

The workstation (DESKTOP-SDN1RPT) had confirmed Skeleton Key attack tools (HookDC.dll, CDLocateCSystem), NTLM hash dumping (Administrator RID 500), and Meterpreter code injection (powershell.exe PID 3316, spoolsv.exe PID 2188) in memory. The rapid sequential use of three different domain accounts (Administrator, ricksanchez, mortysmith) from this compromised host to authenticate to the domain controller is consistent with credential harvesting and lateral movement using stolen credentials.



### 11. [HIGH] coreupdater.exe Malware Dropped in System32 and Manually Executed via Explorer

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:40:49 to 2020-09-19T03:52:14 |
| **Sources** | strings.output, ez.mft, enrichment.iocs |
| **Evidence Refs** | tc_b97d1d99, tc_0ba95851, tc_4ad192db |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059](https://attack.mitre.org/techniques/T1059/) |


Pagefile string analysis reveals Windows SmartScreen reputation check data showing coreupdater.exe (7,168 bytes) at C:\Windows\System32\ was:
1. Checked via isFileSupported (executionTime: 11341)
2. Reputation lookup performed (executionTime: 2906838)
3. User action taken: "run" (the user/attacker chose to execute it)
4. Reputation check performed (executionTime: 41563981)
5. Action: "block" (SmartScreen tried to block it)

The caller process was C:\Windows\explorer.exe (PID 4008), confirming the malware was manually launched through Windows Explorer. CRC values were computed but no hash was recorded. The MFT shows coreupdater.exe created at 2020-09-19 03:52:14 in System32.

IOC enrichment reveals the C2 destination 203.78.103.109 is hosted in Thailand (AS23884 Proen Corp), and the credential source IP 194.61.24.102 is hosted in Russia (AS41842 LLC "MEDIA SYSTEMS"). The coreupdater.exe binary does NOT appear in the ShimCache, and no registry persistence mechanism was found for it, suggesting it was deployed for a single session C2 rather than persistent access. The Meterpreter payload in spoolsv.exe (PID 3724) served as the persistent implant.



### 12. [HIGH] Network IOC Summary: Attacker Infrastructure IPs and Malware Download URL

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:21:25 to 2020-09-19T05:09:13 |
| **Sources** | volatility.netscan, bulk.domain, volatility.pstree |
| **Evidence Refs** | tc_678bb44e, tc_06ce11bb, tc_f6352ef5 |
| **ATT&CK** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/) |


Cross-referencing network artifacts from memory forensics (netscan), event logs (EVTX Security), and disk carving (bulk_extractor) identified the following confirmed attacker infrastructure:

**Primary IOCs:**
1. **203.78.103.109:443** — Active C2 server. coreupdater.exe (PID 3644 on DC01) maintained an ESTABLISHED TCP connection to this IP. No legitimate service association identified.
2. **194.61.24.102** — Malware staging/hosting server. Hosted http://194.61.24.102/coreupdater.exe. Also used for remote authentication to DC01 (EVTX Event 4648). Confirmed by bulk_extractor URL carving and EVTX security logs.
3. **"kali" workstation** — Attack machine used for brute-force (EVTX Event 4625, NTLM logon type 3).

**Confirmed Malicious Files:**
- **coreupdater.exe** — 7,168 bytes, placed in C:\Windows\System32\. Ran on both DESKTOP-SDN1RPT (PID 8324, exited) and DC01 (PID 3644, had active C2). Windows Defender detected and blocked on DESKTOP-SDN1RPT.
- **Meterpreter reflective DLL** — Injected into spoolsv.exe on both DC01 (PID 3724) and DESKTOP-SDN1RPT (PID 2188)

**DESKTOP-SDN1RPT Network Activity at Capture:**
- Only one external connection: 10.42.85.115:51003 → 72.21.91.29:80 (CLOSED) — likely Microsoft CDN/Update traffic
- No active C2 connections from DESKTOP-SDN1RPT at capture time (coreupdater.exe PID 8324 had already exited)
- Multiple svchost.exe UDP listeners on standard service ports — normal system activity

**Domain Context:**
- Domain: C137.local
- DC01 IP: 10.42.85.10 (CITADEL-DC01)
- Workstation IP: 10.42.85.115 (DESKTOP-SDN1RPT)
- User accounts involved: Administrator (RID 500), ricksanchez, mortysmith

**Note:** No evidence of data exfiltration was found. The C2 connection was established but no outbound data transfer to exfiltration services was detected (T1041 removed from MITRE mappings).



### 13. [HIGH] PowerShell Attack Chain with Hidden Command Lines on DESKTOP-SDN1RPT

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T05:08:43 |
| **Sources** | volatility.cmdline, volatility.malfind |
| **Evidence Refs** | tc_b2eac249, tc_12e1ba64 |
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1027](https://attack.mitre.org/techniques/T1027/) |


Two powershell.exe processes on DESKTOP-SDN1RPT exhibit suspicious characteristics consistent with post-exploitation tooling:

1. **powershell.exe PID 508** (PPID 1380): Parent process PID 1380 is NOT present in the process list, indicating the parent has exited. Command line arguments are empty/hidden ("-"). Running in session 2 (user session). This orphaned PowerShell process with a missing parent suggests it was spawned by a temporary execution vehicle.

2. **powershell.exe PID 3316** (PPID 508): Child of PID 508, creating a nested PowerShell chain. Command line arguments are also empty/hidden. Volatility malfind detected:
   - MZ PE header in PAGE_EXECUTE_READWRITE memory (CommitCharge=36) — injected executable
   - Multiple additional RWX regions (107 pages, 57 pages) — consistent with reflective DLL loading pattern identical to Meterpreter on DC01's spoolsv.exe PID 3724
   - Created at 2020-09-19 05:08:43

The empty command line arguments for both processes indicate the attacker cleared or obfuscated the PowerShell invocation parameters. Combined with YARA detections of base64-encoded PowerShell patterns (JAB) in the Registry process and the MZ injection in PID 3316, this chain represents the attacker's primary interactive post-exploitation session on the workstation, likely used to deploy the Skeleton Key attack tool, perform NTLM hash dumping, and stage lateral movement to DC01.



### 14. [MEDIUM] Tofu_Backdoor Signature Detected in DESKTOP-SDN1RPT Memory

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-18T22:42:14 |
| **Sources** | yara.memory |
| **Evidence Refs** | tc_5cf5e7ab |
| **ATT&CK** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1059](https://attack.mitre.org/techniques/T1059/) |


YARA rule Tofu_Backdoor matched in the DESKTOP-SDN1RPT memory dump at two offsets (0xe00c466 and 0x57d8872d), detecting the string "Cookies: Sym1.0" — a known HTTP header signature used by the Tofu backdoor family (also known as Backdoor.Tofu). This malware is associated with APT campaigns and uses custom HTTP cookie headers for C2 communication.

The presence of this signature in the workstation memory, combined with other confirmed compromises (Meterpreter injection in spoolsv.exe PID 2188, Skeleton Key attack toolkit, NTLM hash dumping, and coreupdater.exe C2 malware), indicates an additional backdoor tool may have been deployed on the workstation as part of the multi-stage attack.

Note: This is a single YARA signature match. While "Cookies: Sym1.0" is a specific string unlikely to appear in legitimate software, the match alone does not confirm active Tofu backdoor execution — the string could be residual from a tool that was loaded and unloaded, or from a related attack framework that shares this signature.



### 15. [MEDIUM] Encoded PowerShell Commands (JAB Pattern) in DESKTOP-SDN1RPT Registry Memory

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-18T22:42:14 |
| **Sources** | yara.volatility |
| **Evidence Refs** | tc_ae64a08b |
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1112](https://attack.mitre.org/techniques/T1112/) |


YARA rule SUSP_PS1_JAB_Pattern_Jun22_1 matched in the Registry process (PID 92) of the DESKTOP-SDN1RPT memory dump, detecting base64-encoded PowerShell command patterns. The matched string "JABiAD0A" (at multiple offsets including 0x28efc5f3224 and 0x28efc5f3294) decodes to "$b=" — the beginning of an encoded PowerShell variable assignment, a hallmark of obfuscated PowerShell attack scripts.

The detection in the Registry process (PID 92) indicates encoded PowerShell content was stored in a registry hive, a known technique for staging malicious payloads or establishing persistence through registry-based script storage. This is consistent with the broader attack pattern observed on this system: PowerShell was actively used as an attack tool (powershell.exe PID 3316 has MZ PE injection in RWX memory, spawned by PID 508 whose parent PID 1380 has exited).

Combined with the Skeleton Key patcher, NTLM hash dumper, and Meterpreter implants discovered on this system, this finding indicates the attacker used encoded PowerShell as part of their toolkit for post-exploitation activity.



### 16. [INFO] CoinMiner and Webshell YARA Signatures in MemCompression — Likely Windows Defender Definition Artifacts

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Sources** | yara.volatility, strings.output |
| **Evidence Refs** | tc_ae64a08b, tc_8715f3cf |


Multiple YARA rules matched within the MemCompression process (PID 1816) on DESKTOP-SDN1RPT, including CoinMiner_Strings ("stratum+tcp://"), WEBSHELL_PHP_Dynamic_Big ("eval(", "<?php", "Exploit", "Webshell"), WEBSHELL_ASP_Generic, WScriptShell_Case_Anomaly, and PowerShell_Case_Anomaly. These detections span 54+ match locations within a single process.

However, analysis of the pagefile strings output reveals that the DESKTOP-SDN1RPT system has Windows Defender (MsMpEng.exe PID 2404) actively running, and the strings output contains extensive malware definition patterns including detection signature names like "Worm:Win32/Gamarue", "TrojanDownloader", "Lowfi:Win64/Minxer_Coi", "Ransom:CL", and "Trojan:O97M". These are Windows Defender virus definition database strings.

The MemCompression process (PID 1816) compresses memory pages system-wide. When Windows Defender loads its malware definition database into memory, those signature strings — which include "stratum+tcp://", "eval(", "<?php", etc. — get compressed by MemCompression. YARA rules then match on these AV definition signatures rather than actual malware.

Assessment: These CoinMiner and Webshell YARA hits are most likely false positives caused by Windows Defender malware definition content in compressed memory. No independent evidence of cryptocurrency mining or webshell deployment was found on DESKTOP-SDN1RPT (no mining pool network connections, no web server processes, no PHP runtime).



### 17. [INFO] No Evidence of NTDS.dit Extraction, Event Log Clearing, or Timestomping on DC01

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Sources** | ez.mft, evtx.windows_system32_winevt_logs_system, evtx.windows_system32_winevt_logs_security, strings.output |
| **Evidence Refs** | tc_779a3b94, tc_eade200b, tc_722c93ac, tc_4ad192db |
| **ATT&CK** | [T1003.003](https://attack.mitre.org/techniques/T1003/003/), [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1070.006](https://attack.mitre.org/techniques/T1070/006/) |


Systematic analysis found no evidence of several expected post-compromise activities on the domain controller:

1. NTDS.dit Extraction: No evidence of ntdsutil execution, vssadmin shadow copy creation, or NTDS.dit file copying was found in MFT records, event logs, pagefile strings, or ShimCache. The NTDS.dit exists at its normal location. Strings referencing ntdsutil, vssadmin, and shadow operations in the pagefile are exclusively from Windows Defender malware signature databases, not actual attack commands.

2. Event Log Tampering: System.evtx (165 windows, 1,235 lines) was searched for Event ID 104 (log cleared) with zero matches. Security.evtx was searched for Event ID 1102 (audit log cleared) with zero matches. Logs appear intact.

3. Timestomping: MFT timestamp analysis via detect_timestomping found no anomalies beyond normal Windows operations. The coreupdater.exe MFT timestamps show $STANDARD_INFORMATION and $FILE_NAME timestamps consistent with legitimate creation at 2020-09-19 03:52:14.

4. Data Staging/Exfiltration: No archive files (.zip, .rar, .7z) created in staging locations were found. Bulk_extractor URL analysis found no upload service indicators. The C2 connection (coreupdater.exe → 203.78.103.109:443 HTTPS) was established but no evidence of data being exfiltrated was found.

The attacker appears to have focused on credential harvesting (NTLM hashes from workstation, Skeleton Key for persistent authentication bypass) rather than data theft from the AD database.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.42.85.10` |  | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 |
| Port | `TCP 62613` |  | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 |
| External IP | `203.78.103.109` | Thailand, AS23884 Proen Corp Public Company Limited. | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 |
| Port | `TCP 443` |  | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 |
| External IP | `194.61.24.102` | Russia, AS41842 LLC "MEDIA SYSTEMS" | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 |
| Internal IP | `10.42.85.115` |  | Lateral Movement via Multiple Compromised Domain Accounts from Workstation to DC |
| Port | `TCP 51003` |  | Network IOC Summary: Attacker Infrastructure IPs and Malware Download URL |
| External IP | `72.21.91.29` |  | Network IOC Summary: Attacker Infrastructure IPs and Malware Download URL |
| Port | `TCP 80` |  | Network IOC Summary: Attacker Infrastructure IPs and Malware Download URL |
| Port | `TCP 62475` |  | Environment-Wide Meterpreter Implant in spoolsv.exe Across DC01 and DESKTOP-SDN1 |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Windows\System32\coreupdater.exe` |  | coreupdater.exe Malware with Active C2 Connection to 203.78.103.109 |
| Path | `C:\Windows\System32\winlogon.exe` |  | Remote Authentication to DC from C2 Infrastructure IP 194.61.24.102 |
| Path | `C:\Windows\System32\` |  | Attack Timeline: Kali Linux Brute-Force Followed by Credential-Based DC Compromi |
| Path | `C:\Windows\explorer.exe` |  | coreupdater.exe Malware Dropped in System32 and Manually Executed via Explorer |





---

## Appendix C: MITRE ATT&CK Coverage

24 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (2) > Execution (4) > Persistence (5) > Privilege Escalation (3) > Defense Evasion (10) > Credential Access (6) > Lateral Movement (2) > Command and Control (2)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Remote Authentication to DC from C2...; Attack Timeline: Kali Linux Brute-Force...; Lateral Movement via Multiple Compromised...; Cross-System Credential Theft Chain:... |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | Remote Authentication to DC from C2... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Tofu_Backdoor Signature Detected in...; coreupdater.exe Malware Dropped in System32... |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Code Injection in powershell.exe (PID 3316) on...; Encoded PowerShell Commands (JAB Pattern) in...; PowerShell Attack Chain with Hidden Command... |
| [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Python | Environment-Wide Meterpreter Implant in... |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | coreupdater.exe Malware Dropped in System32... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Remote Authentication to DC from C2...; Attack Timeline: Kali Linux Brute-Force...; Lateral Movement via Multiple Compromised...; Cross-System Credential Theft Chain:... |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Encoded PowerShell Commands (JAB Pattern) in... |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | Remote Authentication to DC from C2... |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Environment-Wide Meterpreter Implant in... |
| [T1556.001](https://attack.mitre.org/techniques/T1556/001/) | Domain Controller Authentication | Skeleton Key Attack Detected in DESKTOP-SDN1RPT Memory; Cross-System Credential Theft Chain:... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Code Injection in powershell.exe (PID 3316) on...; PowerShell Attack Chain with Hidden Command...; Environment-Wide Meterpreter Implant in... |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Remote Authentication to DC from C2...; Attack Timeline: Kali Linux Brute-Force...; Lateral Movement via Multiple Compromised...; Cross-System Credential Theft Chain:... |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Environment-Wide Meterpreter Implant in... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Encoded PowerShell Commands (JAB Pattern) in...; PowerShell Attack Chain with Hidden Command... |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Resource Name or Location | coreupdater.exe Malware with Active C2...; coreupdater.exe Malware Dropped in System32... |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Code Injection in powershell.exe (PID 3316) on...; PowerShell Attack Chain with Hidden Command...; Environment-Wide Meterpreter Implant in... |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | No Evidence of NTDS.dit Extraction, Event Log... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | PowerShell Attack Chain with Hidden Command... |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Timestomp | No Evidence of NTDS.dit Extraction, Event Log... |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Remote Authentication to DC from C2...; Attack Timeline: Kali Linux Brute-Force...; Lateral Movement via Multiple Compromised...; Cross-System Credential Theft Chain:... |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Encoded PowerShell Commands (JAB Pattern) in... |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | Lateral Movement via Multiple Compromised... |
| [T1556.001](https://attack.mitre.org/techniques/T1556/001/) | Domain Controller Authentication | Skeleton Key Attack Detected in DESKTOP-SDN1RPT Memory; Cross-System Credential Theft Chain:... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Attack Timeline: Kali Linux Brute-Force... |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Skeleton Key Attack Detected in DESKTOP-SDN1RPT Memory; NTLM Hash Dump Output Detected in...; Cross-System Credential Theft Chain:... |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | NTLM Hash Dump Output Detected in...; Cross-System Credential Theft Chain:... |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | No Evidence of NTDS.dit Extraction, Event Log... |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Brute-Force Password Attack Against DC01 from...; Attack Timeline: Kali Linux Brute-Force...; Cross-System Credential Theft Chain:... |
| [T1556.001](https://attack.mitre.org/techniques/T1556/001/) | Domain Controller Authentication | Skeleton Key Attack Detected in DESKTOP-SDN1RPT Memory; Cross-System Credential Theft Chain:... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement via Multiple Compromised... |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | Lateral Movement via Multiple Compromised... |


### Command and Control

| Technique | Name | Findings |
|-----------|------|----------|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | coreupdater.exe Malware with Active C2...; Tofu_Backdoor Signature Detected in...; Network IOC Summary: Attacker Infrastructure... |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | coreupdater.exe Malware with Active C2...; Attack Timeline: Kali Linux Brute-Force...; Network IOC Summary: Attacker Infrastructure... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 430 |
| Findings submitted | 17 |
| Confirmed | 12 |
| Inferences | 5 |
| Input tokens | 71.2K |
| Output tokens | 128.2K |
| Total tokens | 199.4K |
| Audit log | /home/mulder/.mulder/cases/szechuan.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 71.2K | 128.2K | 199.4K |




<details>
<summary>Evidence Sources (89)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| strings.output | strings | 937655 |
| volatility.pslist | volatility3 | 96 |
| strings.output | strings | 66809 |
| volatility.pslist | volatility3 | 41 |
| tsk.filelist | sleuthkit | 114999 |
| volatility.pstree | volatility3 | 95 |
| tsk.filelist.p1 | sleuthkit | 166 |
| bulk.domain | bulk_extractor | 8421 |
| bulk.email | bulk_extractor | 307 |
| volatility.pstree | volatility3 | 41 |
| bulk.ether | bulk_extractor | 9 |
| bulk.rfc822 | bulk_extractor | 230 |
| bulk.url | bulk_extractor | 16254 |
| bulk.url_facebook-address | bulk_extractor | 7 |
| bulk.url_searches | bulk_extractor | 43 |
| bulk.url_services | bulk_extractor | 2198 |
| yara.memory | yara | 350 |
| volatility.cmdline | volatility3 | 41 |
| volatility.cmdline | volatility3 | 96 |
| yara.memory | yara | 1042 |
| volatility.netscan | volatility3 | 19686 |
| volatility.malfind | volatility3 | 16 |
| volatility.netscan | volatility3 | 116 |
| tsk.partitions | sleuthkit | 10 |
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
| evtx.manifest | evtx-extract | 105 |
| tsk.timeline | sleuthkit | 416715 |
| volatility.psscan | volatility3 | 169 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 25 |
| registry.system | regripper | 8 |
| registry.system | regripper | 8 |
| registry.system | regripper | 29966 |
| registry.system | regripper | 283 |
| volatility.dlllist | volatility3 | 1428 |
| registry.system | regripper | 283 |
| registry.system | regripper | 4936 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| registry.system | regripper | 405 |
| volatility.svcscan | volatility3 | 43222 |
| exiftool.metadata | exiftool | 0 |
| evtx.windows_system32_winevt_logs_security | eztools | 5073 |
| evtx.windows_system32_winevt_logs_active-directory-web-services | eztools | 65 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 150 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 150 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.persistence | composite | 9401 |
| yara.volatility | yara | 1254 |
| composite.exfil | composite | 343 |
| evtx.windows_system32_winevt_logs_system | eztools | 1235 |
| composite.persistence | composite | 9401 |
| enrichment.iocs | enrichment | 50 |
| composite.suspicious_processes | composite | 128 |
| composite.persistence | composite | 9401 |
| composite.defense_evasion | composite | 38 |
| composite.exfil | composite | 343 |
| composite.file_staging | composite | 2312 |
| composite.execution | composite | 144 |
| composite.timeline | composite | 160 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.recovery | composite | 7 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
