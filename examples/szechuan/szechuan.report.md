# Mulder Investigation Report

**Case:** szechuan
**Generated:** 2026-06-06T16:18:28.128018+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 118 evidence sources (19 memory, 22 disk, 77 other) | 516 tool calls | 1.0 hours
**Results:** 26 findings (8 critical, 8 high) | 19 confirmed, 7 inference
**Timeline:** 2020-09-18 to 2020-09-19

**Key Threats:**
- Meterpreter (Metasploit) Implant Detected in DC01 Memory
- Meterpreter Shellcode Injection in spoolsv.exe (PID 3724)
- Explicit Credential Logon from Malware Staging Server IP 194.61.24.102
- Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure
- Anomalous Network Listener on spoolsv.exe Port 62475 - Meterpreter Bind Shell Indicator

**Attack Lifecycle:**
- **Initial Access / Deployment** (2020-09-19): Meterpreter (Metasploit) Implant Detected in DC01 Memory (+13 related)
- **Persistence** (2020-09-18 to 2020-09-19): PCAP Traffic Profile: Encrypted Attack Channels Evaded IDS Detection (+4 related)
- **Lateral Movement** (2020-09-19): DESKTOP-SDN1RPT SMB Connection to Compromised Domain Controller DC01 (+1 related)
- **Command and Control** (2020-09-19): Hidden Processes on DESKTOP-SDN1RPT: psscan vs pslist Discrepancy (6 PIDs)
- **Credential Access** (2020-09-19): Brute Force Password Attack from "kali" Workstation Against Administrator Account

**Tools:** search (127), get_raw_output (61), submit_finding (31), open_case (18), extract_archive (16). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Meterpreter (Metasploit) Implant Detected in DC01 Memory** (2020-09-19T01:22:38+00:00)


- **Meterpreter Shellcode Injection in spoolsv.exe (PID 3724)** (2020-09-19T01:22:57+00:00)


- **Explicit Credential Logon from Malware Staging Server IP 194.61.24.102** (2020-09-19T03:22:09+00:00 to 2020-09-19T03:22:37+00:00)


- **Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure** (2020-09-19T03:40:49+00:00 to 2020-09-19T03:43:10+00:00)


- **Anomalous Network Listener on spoolsv.exe Port 62475 - Meterpreter Bind Shell Indicator** (2020-09-19T03:29:40)


- **Complete Attack Timeline: External Brute Force to Domain Controller Compromise** (2020-09-19T03:12:46Z to 2020-09-19T03:43:10)


- **Active C2 Connections from DESKTOP-SDN1RPT to 203.78.103.109:443** (2020-09-19T03:40:49+00:00)


- **Cross-System C2 Infrastructure: Both DC01 and DESKTOP-SDN1RPT Connected to 203.78.103.109:443** (2020-09-19T01:22:57+00:00)




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

516 tool calls were executed across 41
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Digital Forensic Investigation Report — Case "Szechuan"

## Background

This investigation was initiated in response to a suspected network intrusion affecting the C137 Active Directory domain environment. The evidence corpus comprised forensic acquisitions from two Windows systems and one network capture, all collected on or around September 19, 2020. The primary evidence items were:

- **CITADEL-DC01** (10.42.85.10): A Windows Server 2012 R2 domain controller. Evidence included a full disk image (E01 format) and a physical memory dump (citadeldc01.mem).
- **DESKTOP-SDN1RPT** (10.42.85.115): A Windows 10 domain-joined workstation. Evidence included a full disk image and a physical memory dump (desktop-sdn1rpt.mem).
- **Network capture** (PCAP): A 197 MB packet capture containing 411,797 packets spanning approximately 7.7 hours (2020-09-18 21:58:07 to 2020-09-19 05:38:57 UTC).
- **Protected files archives**: Forensic collections of credential material (registry hives, NTDS.dit, DPAPI keys) from both systems, packaged by the investigating team for offline analysis.

The investigation consumed 41 indexed evidence sources across 19 distinct extractor types, including Volatility 3 memory forensics, Sleuth Kit disk analysis, YARA signature scanning, Zeek and Suricata network analysis, EZ Tools Windows artifact parsing, bulk_extractor IOC carving, ClamAV and Chainsaw/Hayabusa detection, and multiple composite cross-correlation analyses. A total of 516 tool invocations were executed. The analysis produced 26 findings — 8 critical, 8 high, 5 medium, 2 low, and 3 informational — with 19 corroborated by multiple independent sources and 7 assessed as reasonable inferences from available evidence. 0 findings were ruled out as false positives during the investigation. The findings collectively map to 25 distinct MITRE ATT&CK technique identifiers.

The C137 domain was a small Active Directory environment with at least four user accounts on the workstation (Administrator, ricksanchez, mortysmith, and Admin) and the standard domain administrator account on DC01. The workstation ran Windows 10 with Windows Defender active, while the domain controller ran Windows Server 2012 R2 with no effective endpoint protection — a disparity that proved decisive in the outcome of the attack.

## Incident Timeline

The reconstructed timeline spans from approximately 03:12 UTC to 05:09 UTC on September 19, 2020, encompassing five distinct operational phases. All timestamps are derived from corroborating evidence across memory forensics, Windows Event Logs, network packet captures, and disk artifacts.

**Phase 1 — Reconnaissance and Initial Access (03:12–03:22 UTC)**

The attack began at 03:12:46 UTC when an Nmap RDP reconnaissance probe was sent from external IP address 194.61.24.102 (Russia, AS41842 LLC "MEDIA SYSTEMS") to the domain controller CITADEL-DC01 on port 3389. The Zeek RDP log captured this connection with a characteristic cookie value of "nmap" and security protocol "HYBRID_EX," unambiguously identifying the tool used for service discovery.

Approximately two minutes later, at 03:14:46 UTC, the attacker launched an automated RDP brute force attack against the Administrator account. Zeek captured roughly 100 rapid connection attempts over a 21-second window (03:14:46 to 03:15:07 UTC), all from sequential source ports (40044 through 40234) with a cookie value of "Administrator" and intervals of approximately 200 milliseconds. The HYBRID security protocol indicated that Network Level Authentication was enforced, meaning the attacker needed valid credentials to establish a session.

The brute force attack shifted methods shortly after. Windows Security Event Log entries (Event ID 4625) on CITADEL-DC01 recorded six rapid failed logon attempts between 03:21:25 and 03:21:30 UTC, each targeting the "\Administrator" account via NTLM authentication (LogonType 3). The source workstation was named "kali," directly indicating an attacker system running Kali Linux. The error substatus 0xC000006A confirmed the username was correct but the password was wrong — a classic brute force signature.

The password attack succeeded. At 03:22:09 UTC, Security Event 4648 recorded a successful explicit credential logon for C137\Administrator originating from IP 194.61.24.102, processed by winlogon.exe (PID 0x9F0) on CITADEL-DC01. A second explicit credential event at 03:22:37 UTC from the same IP confirmed sustained access. The attacker had obtained Domain Administrator credentials.

**Phase 2 — Malware Deployment (03:17–03:29 UTC)**

With administrative access established, the attacker deployed a custom malicious binary. Zeek PE analysis detected the first portable executable file transfer at 03:17:06 UTC. The binary exhibited several hallmarks of malicious tooling: an AMD64 architecture with a WINDOWS_GUI subsystem, a falsified compile timestamp of April 15, 2010 (inconsistent with the 2020 attack), all security mitigations disabled (no ASLR, no DEP, no Code Integrity), no certificate table or debug information, and a non-standard PE section named ".lhru" — a section name not found in any legitimate Windows binary.

The malware was placed at C:\Windows\System32\coreupdater.exe on the domain controller (inode 87137 on the DC01 disk image), masquerading as a legitimate system update component. No corresponding Windows service was registered for this binary, and it was absent from the ShimCache, indicating it was recently dropped and executed directly rather than through the Service Control Manager. The file was hosted on the attacker's staging server at http://194.61.24.102/coreupdater.exe, as confirmed by bulk_extractor URL carving from both systems' disk images.

**Phase 3 — Execution and Command-and-Control Establishment (~03:29 UTC)**

At 03:29:40 UTC, the attacker injected a Meterpreter payload into the Windows Print Spooler service (spoolsv.exe, PID 3724) on DC01 using Metasploit's reflective DLL injection technique. Volatility malfind identified four injected memory regions in PID 3724, all with PAGE_EXECUTE_READWRITE protections. The first region contained the classic Metasploit x64 shellcode prologue (FC 48 89 CE 48 81 EC 00 20 — cld; mov rsi, rcx; sub rsp, 0x2000) followed by PEB traversal code for hash-based API resolution. Three additional regions contained complete MZ PE headers, including the distinctive "MZARUH" reflective loader stub. YARA scanning independently confirmed the HKTL_Meterpreter_inMemory signature, matching metsrv.x64.dll at five distinct memory offsets and ReflectiveLoader at fifteen offsets.

Simultaneously, coreupdater.exe ran as PID 3644 on DC01 and established an HTTPS command-and-control connection to 203.78.103.109:443 (Thailand, AS23884 Proen Corp Public Company Limited). The Meterpreter-injected spoolsv.exe also opened a bind listener on TCP port 62475 — an anomalous high port with no legitimate print spooler function — providing an additional avenue for attacker access.

**Phase 4 — Lateral Movement and Expansion (03:22–03:43 UTC)**

At 03:22:35 UTC, the attacker used the compromised Administrator account to initiate an RDP lateral movement session from CITADEL-DC01 (10.42.85.10:62514) to the workstation DESKTOP-SDN1RPT (10.42.85.115:3389). Corresponding Kerberos TGS ticket requests were captured in zeek.kerberos for the Administrator/C137.LOCAL principal, targeting services including host/desktop-sdn1rpt, ldap/CITADEL-DC01.C137.local, cifs, and ProtectedStorage/CITADEL-DC01.

Post-compromise Active Directory enumeration was observed via DCE/RPC and Kerberos protocols. The 209 DCE/RPC records included DRSUAPI operations (DRSBind, DRSCrackNames), lsarpc SID-to-name lookups, and samr security descriptor queries against the SAM database. Critically, DRSGetNCChanges — the operation used in DCSync attacks — was NOT observed in the Zeek DCE/RPC logs.

At 03:33:18 UTC, a second identical PE file was transferred over the network, corresponding to the deployment of coreupdater.exe to DESKTOP-SDN1RPT. The binary executed as PID 8324 at 03:40:49 UTC. However, unlike DC01, the workstation had Windows Defender active, which performed a reputation check on the 7,168-byte payload and executed a "block" action. The process terminated at 03:43:10 UTC after approximately 2.5 minutes of execution.

**Phase 5 — Sustained Access and Persistent Control (post-03:29 UTC)**

Despite Windows Defender blocking the initial coreupdater.exe payload on DESKTOP-SDN1RPT, the attacker achieved persistent code injection on the workstation through alternative means. Volatility malfind detected injected MZ PE headers in spoolsv.exe (PID 2188) with the same reflective injection pattern observed on DC01. Additionally, powershell.exe (PID 3316) contained multiple injected RWX memory regions including a complete PE header. This PowerShell process was part of a suspicious execution chain: an unknown parent process (PID 1380, absent from the process tree) spawned PID 508 (powershell.exe, which ran briefly from 05:08:37 to 05:08:43 UTC), which in turn spawned PID 3316 (powershell.exe, still running at memory capture). Neither PowerShell process had command line data available in memory.

Two simultaneous ESTABLISHED TCP connections from DESKTOP-SDN1RPT to 203.78.103.109:443 confirmed active C2 at the time of memory capture, demonstrating the attacker maintained unified control across both systems through the same Thai-hosted infrastructure.

## Key Findings

**Meterpreter Implant and Process Injection**

The most significant finding of this investigation is the confirmed presence of an active Metasploit Meterpreter implant operating within the domain controller's memory. Three independent detection methods — YARA signature matching (HKTL_Meterpreter_inMemory), Volatility malfind code injection analysis, and network connection correlation — converge on the same conclusion. The implant was injected into spoolsv.exe (PID 3724) via reflective DLL injection, a technique where a DLL is loaded directly into process memory without touching disk, making it invisible to traditional file-based scanning. The Print Spooler service was a deliberate choice: it runs as SYSTEM with network capabilities, providing the attacker with the highest privilege level and the ability to maintain network communications.

The counter-analysis performed during the investigation specifically addressed whether the YARA matches could be false positives from antivirus signature database memory. This was ruled out based on three factors: the metsrv.x64.dll and ReflectiveLoader strings clustered at offsets 15 bytes apart — matching the internal layout of an intact metsrv.dll binary; malfind independently confirmed executable shellcode in PAGE_EXECUTE_READWRITE memory (not a signature store); and DC01 had no effective AV engine whose signature store could produce such artifacts.

On DESKTOP-SDN1RPT, the same injection pattern was observed in spoolsv.exe (PID 2188) and powershell.exe (PID 3316), though YARA vadyarascan was not executed against that system's memory. The injection was assessed as Meterpreter based on the identical injection technique, the shared C2 infrastructure, and the temporal coherence with the broader attack chain.

**Attacker Infrastructure**

The attacker operated from geographically distributed infrastructure. The staging and initial access server at 194.61.24.102 was located in Russia (AS41842 LLC "MEDIA SYSTEMS") and served dual purposes: hosting the coreupdater.exe payload for download and serving as the source IP for RDP brute force and explicit credential authentication. The command-and-control server at 203.78.103.109 was located in Thailand (AS23884 Proen Corp Public Company Limited) and received encrypted HTTPS callbacks from both compromised systems over port 443, blending C2 traffic with legitimate web browsing.

A third IP address, 92.63.197.153, initially appeared as a potential IOC but was conclusively determined to be cached Windows Defender antivirus signature data embedded in pagefile content. Every occurrence was surrounded by malware family name strings (Zonidel, Anatova, etc.) characteristic of AV definition databases, and the IP appeared in no network connections, event logs, MFT entries, browser history, or PCAP data.

**Malware Characteristics**

The coreupdater.exe binary (7,168 bytes) was a compact Metasploit-generated payload masquerading as a legitimate Windows system utility. Key attributes included: all security mitigations disabled (no ASLR, no DEP, no Code Integrity), a falsified compile timestamp predating the attack by a decade, a non-standard PE section name (.lhru), and no digital signature. The small file size is consistent with a Metasploit stager payload designed to download and execute the full Meterpreter implant in memory.

**Lateral Movement**

Lateral movement was confirmed via RDP from the domain controller to the workstation at 03:22:35 UTC, approximately seven minutes after the attacker obtained Administrator credentials. This direction — domain controller to workstation — is inherently suspicious and atypical of normal administrative activity. The movement was authenticated using Kerberos TGS tickets for multiple services, including ProtectedStorage, suggesting the attacker sought access to credential stores on the workstation.

**Defensive Disparity**

The investigation revealed a stark contrast in endpoint security between the two systems. DESKTOP-SDN1RPT's Windows Defender successfully detected and blocked coreupdater.exe, terminating the process after 2.5 minutes. CITADEL-DC01, running Windows Server 2012 R2, had no effective endpoint protection, allowing the Meterpreter implant to persist unchallenged. This disparity was the single most consequential factor in the depth of the domain controller compromise.

## Threat Intelligence and Attribution

The tactics, techniques, and procedures observed in this incident are consistent with a moderately sophisticated adversary employing widely available offensive tooling. The use of Metasploit Framework (Meterpreter with reflective DLL injection), Nmap for reconnaissance, and a system named "kali" collectively point to an attacker operating from a standard penetration testing platform. The attack demonstrated competence in Active Directory exploitation and process injection but did not employ advanced custom tooling, zero-day exploits, or kernel-level rootkit capabilities.

The infrastructure pattern — a Russian-hosted staging server combined with a Thai-hosted C2 node — suggests deliberate geographic compartmentalization to complicate takedown and attribution. The use of commodity hosting providers (AS41842 and AS23884) rather than bulletproof hosting or compromised infrastructure is consistent with financially motivated actors or less-resourced threat groups, though it does not exclude state-aligned operators using disposable infrastructure.

The operational tempo of the attack — from initial reconnaissance to full domain compromise in approximately 30 minutes — indicates pre-planned execution with prepared tooling rather than opportunistic scanning. However, the brute force approach to initial access (rather than exploiting a vulnerability or using stolen credentials) suggests the attacker did not have prior insider access to the environment.

The absence of credential dumping tool artifacts (no mimikatz, ntdsutil, secretsdump, or DCSync activity), the lack of data exfiltration indicators, and the absence of anti-forensic countermeasures collectively suggest the attack was either interrupted early in its lifecycle or the attacker's primary objective was establishing persistent access rather than immediate data theft. The evidence does not support definitive attribution to any known threat group or campaign. The tooling and techniques overlap with those used by numerous threat actors ranging from cybercriminal groups to penetration testers, and no unique infrastructure signatures, custom malware families, or distinctive TTPs were observed that would narrow attribution beyond "Metasploit-equipped attacker with RDP brute force capability."

## Impact Assessment

The attacker achieved Domain Administrator-level access to the C137 Active Directory environment, representing a complete compromise of the domain trust boundary. Two systems were confirmed compromised:

**CITADEL-DC01 (Critical Impact):** The domain controller sustained an active Meterpreter implant running as SYSTEM within spoolsv.exe, with an established C2 channel and a bind shell listener on port 62475. As a domain controller, this system held the NTDS.dit database containing all domain user password hashes and Kerberos keys. While no evidence confirmed the attacker extracted these credentials, the capability was fully available through the duration of the compromise.

**DESKTOP-SDN1RPT (High Impact):** Despite Windows Defender blocking the initial malware payload, the workstation was compromised through code injection into spoolsv.exe and powershell.exe. Two active C2 connections to the Thailand-based infrastructure were maintained at the time of memory capture. The ricksanchez user was actively logged in during the compromise, exposing any data accessible to that session.

**Credential Exposure:** The attacker possessed Domain Administrator credentials (obtained via brute force) and had unrestricted access to the NTDS.dit, SAM, SECURITY, and SYSTEM registry hives on both systems. Four user account profiles were present on the workstation (Administrator, ricksanchez, mortysmith, Admin), all with DPAPI master keys that could be decrypted using the domain backup key. The investigation found no evidence of credential dumping tools or DCSync operations, but the absence of evidence does not constitute evidence of absence — the attacker held the keys to extract any credential in the domain.

**Data at Risk:** No evidence of data exfiltration or staging was detected across file system analysis, network captures, and memory forensics. All references to cloud storage services (Mega, Dropbox, Pastebin) were traced to cached AV signature data rather than actual user or attacker activity. The PCAP showed no outbound data transfers to suspicious destinations, no DNS tunneling, and no beaconing patterns. However, the attacker's C2 channel operated over HTTPS (port 443), and any exfiltration through this encrypted channel would not be visible in the available evidence.

**Persistence Depth:** The attacker's persistence was entirely memory-resident. No services, registry autorun keys, scheduled tasks, or disk-based backdoors were installed. This means the compromise would not survive a system restart but was fully operational at the time of evidence collection.

## Immediate Tactical Containment

The following actions should be executed immediately to neutralize the active threat:

1. **Isolate both compromised systems from the network.** Disconnect CITADEL-DC01 (10.42.85.10) and DESKTOP-SDN1RPT (10.42.85.115) from all network segments. Do not power off — memory-resident evidence will be lost.

2. **Block attacker infrastructure at the perimeter firewall.** Create deny rules for 194.61.24.102 (inbound and outbound) and 203.78.103.109 (inbound and outbound) on all egress and ingress points. These IPs serve as the staging server and C2 server respectively.

3. **Terminate malicious processes on DC01.** Kill coreupdater.exe (PID 3644) and restart spoolsv.exe (PID 3724) to clear the injected Meterpreter implant. Close the bind shell listener on TCP port 62475.

4. **Terminate malicious processes on DESKTOP-SDN1RPT.** Restart spoolsv.exe (PID 2188) to clear injected code. Kill powershell.exe (PID 3316) and its console host (PID 728). Investigate any process occupying the two C2 TCP sessions to 203.78.103.109:443 (source ports 50875 and 50972).

5. **Reset the C137\Administrator domain account password immediately.** This credential was brute-forced and used for all lateral movement. Force a password change and revoke all active Kerberos tickets (krbtgt double-reset if DCSync cannot be ruled out).

6. **Reset passwords for all accounts on DESKTOP-SDN1RPT.** The ricksanchez, mortysmith, Admin, and local Administrator accounts all had DPAPI-protected credential stores accessible to the attacker.

7. **Block the malware hash across all endpoints.** Add coreupdater.exe (7,168 bytes, located at C:\Windows\System32\coreupdater.exe) to endpoint detection blocklists. Delete the file from C:\Windows\System32\ on both systems.

8. **Audit RDP access.** Disable external RDP access to CITADEL-DC01 on port 3389 immediately. No domain controller should accept RDP connections from external IP addresses.

9. **Review all Domain Administrator account activity** across the environment for the period 2020-09-19 03:15 UTC onward to identify any additional systems accessed with the compromised credentials.

## Strategic Remediation

**External RDP Exposure on the Domain Controller.** The entire attack chain began because the domain controller's RDP service (port 3389) was directly reachable from the external IP 194.61.24.102, as confirmed by the Nmap probe and brute force attack captured in Zeek RDP logs and Security Event Log entries (findings f_aefe4e49, f_240aa1fe, f_85641e1c). Domain controllers should never have RDP exposed to untrusted networks. The remediation is to place DC01 behind a VPN or jump server architecture, restrict RDP access via Windows Firewall to a defined set of internal management subnets, and enforce Network Level Authentication with account lockout policies that would have terminated the brute force after a configurable number of failures.

**Absence of Endpoint Protection on the Domain Controller.** Windows Defender on DESKTOP-SDN1RPT successfully detected and blocked coreupdater.exe (finding f_fe981a84), while DC01 — running Windows Server 2012 R2 — had no comparable protection, allowing the Meterpreter implant to operate unchallenged (findings f_50a6e547, f_ee80c4fe). The remediation is to deploy endpoint detection and response (EDR) on all domain controllers with at minimum real-time malware scanning, memory injection detection, and anomalous network listener alerting. Had DC01 run the same Defender configuration as DESKTOP-SDN1RPT, the initial coreupdater.exe payload would likely have been blocked.

**Weak or Brute-Forceable Domain Administrator Password.** The attacker successfully brute-forced the C137\Administrator password through approximately 100 RDP attempts over 21 seconds followed by six NTLM attempts over five seconds (findings f_aefe4e49, f_240aa1fe). No account lockout policy triggered during this activity. The remediation is to enforce a minimum 20-character passphrase for all Domain Administrator accounts, implement account lockout after five failed attempts with a 30-minute lockout duration, and configure real-time alerting on Event ID 4625 clusters targeting privileged accounts.

**No Network Segmentation Between Domain Controller and Workstation.** After compromising DC01, the attacker moved laterally to DESKTOP-SDN1RPT via RDP (finding f_1faae5a6) without encountering any network access control between the two hosts. The lack of segmentation allowed the attacker to pivot freely within the flat network. The remediation is to implement microsegmentation that restricts domain controller communications to only required protocols and ports (LDAP, Kerberos, DNS, SMB for Group Policy) and blocks outbound RDP from domain controllers to workstations entirely.

**Encrypted C2 Traffic Invisible to Network Detection.** The attacker's command-and-control channel operated over HTTPS (port 443) to 203.78.103.109, and Suricata IDS with the Emerging Threats ruleset generated zero alerts despite an active compromise (finding f_b934d7c8). All attack operations used standard Windows protocols (RDP, SMB, Kerberos, DCE/RPC) that blended with normal enterprise traffic. The remediation is to deploy TLS inspection on outbound traffic from server segments, implement DNS-based threat intelligence feeds that would flag connections to unrecognized Thai hosting providers, and establish baseline network behavior models that would detect a domain controller initiating outbound connections to previously unseen external IP addresses.

## Conclusion

**Q1. What systems were compromised?** Two systems were confirmed compromised: CITADEL-DC01 (10.42.85.10), the C137 domain controller running Windows Server 2012 R2, and DESKTOP-SDN1RPT (10.42.85.115), a Windows 10 domain-joined workstation. DC01 sustained the deeper compromise with an active Meterpreter implant, while DESKTOP-SDN1RPT was compromised through process injection despite Windows Defender blocking the initial malware payload.

**Q2. How did the attacker gain initial access?** The attacker gained initial access by brute-forcing the C137\Administrator account's password via RDP. The attack originated from 194.61.24.102 (Russia) and progressed through Nmap reconnaissance, automated RDP credential guessing (~100 attempts in 21 seconds), and NTLM brute force, ultimately succeeding at approximately 03:22 UTC on September 19, 2020.

**Q3. What lateral movement occurred?** The attacker moved laterally from CITADEL-DC01 to DESKTOP-SDN1RPT via RDP at 03:22:35 UTC using the compromised Domain Administrator credentials. Kerberos TGS tickets were obtained for multiple services on the workstation. Post-compromise enumeration of Active Directory via DCE/RPC and Kerberos protocols was observed, though individual operations were consistent with normal domain activity when viewed in isolation.

**Q4. What persistence mechanisms were installed?** No traditional persistence mechanisms (registry autorun keys, services, scheduled tasks, or disk-based backdoors) were installed. The attacker's persistence was entirely memory-resident via Meterpreter reflective DLL injection in spoolsv.exe on both systems and in powershell.exe on DESKTOP-SDN1RPT. This approach prioritized stealth over survivability — the implants would not survive a system restart.

**Q5. Was data exfiltrated, and if so, what and how much?** No evidence of data exfiltration was found. Analysis of file staging, network captures (411K packets, 197 MB), DNS tunneling, beaconing patterns, and cloud storage service references all returned negative results. References to file-sharing services in pagefile data were traced to cached AV signature strings. However, the attacker's HTTPS C2 channel would render any encrypted exfiltration invisible to the available evidence, so exfiltration through the C2 channel cannot be definitively excluded.

**Q6. What is the full timeline of the incident?** The confirmed attack window spans from 03:12:46 UTC (Nmap reconnaissance probe) to at least 05:09 UTC (last process activity in DESKTOP-SDN1RPT memory) on September 19, 2020 — a total active window of approximately two hours. The attack progressed through five phases: reconnaissance and brute force (03:12–03:22), malware deployment (03:17–03:29), execution and C2 establishment (~03:29), lateral movement (03:22–03:43), and sustained access (post-03:29). Network traffic in the PCAP extends to 05:38:57 UTC.

**Q7. What is the total scope and business impact?** The scope is a complete Domain Administrator compromise affecting the entire C137 Active Directory domain. All domain user password hashes in NTDS.dit were potentially exposed, all credential stores on both systems were accessible, and the attacker maintained simultaneous C2 channels to both compromised hosts. The business impact includes full loss of confidentiality for all domain credentials, complete loss of integrity for both compromised systems, and a requirement to treat every account in the domain as potentially compromised pending a full credential reset.

**Q8. What are the recommended remediation actions?** Five strategic remediation actions are recommended, each tied to a specific failure observed in this investigation: (1) eliminate external RDP exposure on domain controllers, (2) deploy endpoint protection on all servers to match workstation coverage, (3) enforce strong passwords and account lockout for privileged accounts, (4) implement network segmentation between domain controller and workstation tiers, and (5) deploy TLS inspection and network behavioral analytics to detect encrypted C2 channels that evade signature-based IDS.


---

## Overview

| | |
|---|---|
| Findings | **26** (19 confirmed, 7 inference) |
| Severity | 8 critical, 8 high, 5 medium, 2 low, 3 info |
| Sources | 41 evidence sources across 516 tool calls |


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
| 2020-09-18T21:58:07Z | PCAP Traffic Profile: Encrypted Attack Channels Evaded IDS Detection | MEDIUM | pcap.summary, suricata.alerts, pcap.beaconing, pcap.tunneling, pcap.tls, pcap.http, zeek.dns |
| 2020-09-19T01:22:38+00:00 | Meterpreter (Metasploit) Implant Detected in DC01 Memory | CRITICAL | yara.memory, volatility.malfind |
| 2020-09-19T01:22:38+00:00 | Active Directory Database (NTDS.dit) and Credential Hives Collected for Extraction | MEDIUM | DC01-ProtectedFiles |
| 2020-09-19T01:22:57+00:00 | Meterpreter Shellcode Injection in spoolsv.exe (PID 3724) | CRITICAL | volatility.malfind, volatility.netscan |
| 2020-09-19T01:22:57+00:00 | Cross-System C2 Infrastructure: Both DC01 and DESKTOP-SDN1RPT Connected to 203.78.103.109:443 | CRITICAL | volatility.netscan, composite.pcap_correlation, composite.correlation, enrichment.iocs |
| 2020-09-19T01:24:07+00:00 | DESKTOP-SDN1RPT Credential Hives and DPAPI Keys Collected | MEDIUM | clamav.scan, hashdeep.hashes |
| 2020-09-19T01:24:07+00:00 | Hidden Processes on DESKTOP-SDN1RPT: psscan vs pslist Discrepancy (6 PIDs) | LOW | composite.defense_evasion, composite.suspicious_processes, volatility.psscan |
| 2020-09-19T01:24:09+00:00 | Code Injection in DESKTOP-SDN1RPT spoolsv.exe and powershell.exe | HIGH | volatility.malfind, volatility.pstree |
| 2020-09-19T01:24:10+00:00 | DESKTOP-SDN1RPT SMB Connection to Compromised Domain Controller DC01 | LOW | volatility.netscan |
| 2020-09-19T03:12:46+00:00 | Attacker Infrastructure: Russia-Hosted Staging Server and Thailand-Hosted C2 Server | HIGH | volatility.netscan, bulk.url, bulk.domain |
| 2020-09-19T03:12:46Z | Complete Attack Timeline: External Brute Force to Domain Controller Compromise | CRITICAL | bulk.url, evtx.windows_system32_winevt_logs_security, tsk.filelist, volatility.dlllist, volatility.malfind, volatility.netscan, yara.volatility |
| 2020-09-19T03:12:46Z | RDP Brute Force Attack from 194.61.24.102 Visible in Network Traffic | HIGH | zeek.rdp |
| 2020-09-19T03:16:24Z | Post-Compromise Active Directory Enumeration via DCE/RPC and Kerberos | MEDIUM | zeek.kerberos, zeek.dce_rpc, zeek.smb_files |
| 2020-09-19T03:17:06+00:00 | Malware Masquerading in System32: coreupdater.exe Deployed as Fake System Binary | HIGH | tsk.filelist, volatility.svcscan, ez.shimcache |
| 2020-09-19T03:17:06Z | Suspicious PE Binary Transfer Over Network (coreupdater.exe) | HIGH | zeek.pe, tcpflow.streams |
| 2020-09-19T03:21:25+00:00 | Brute Force Password Attack from "kali" Workstation Against Administrator Account | HIGH | evtx.windows_system32_winevt_logs_security |
| 2020-09-19T03:22:09+00:00 | Explicit Credential Logon from Malware Staging Server IP 194.61.24.102 | CRITICAL | evtx.windows_system32_winevt_logs_security, bulk.url |
| 2020-09-19T03:22:35Z | Lateral Movement via RDP from Domain Controller to Workstation | HIGH | zeek.rdp, zeek.kerberos |
| 2020-09-19T03:29:40 | Anomalous Network Listener on spoolsv.exe Port 62475 - Meterpreter Bind Shell Indicator | CRITICAL | volatility.netscan, volatility.dlllist, yara.volatility |
| 2020-09-19T03:40:49 | DESKTOP-SDN1RPT Targeted with coreupdater.exe - Blocked by Windows Defender | MEDIUM | volatility.pstree, strings.output, bulk.url |
| 2020-09-19T03:40:49+00:00 | Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure | CRITICAL | bulk.url, strings.output, volatility.netscan, volatility.pstree |
| 2020-09-19T03:40:49+00:00 | Active C2 Connections from DESKTOP-SDN1RPT to 203.78.103.109:443 | CRITICAL | volatility.netscan, enrichment.iocs, volatility.pstree |
| 2020-09-19T05:08:37+00:00 | Suspicious PowerShell Execution Chain with Orphaned Parent Process | HIGH | volatility.cmdline, volatility.malfind, volatility.pstree |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Meterpreter (Metasploit) Implant Detected in DC01 Memory

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T01:22:38+00:00 |
| **Sources** | yara.memory, volatility.malfind |
| **Evidence Refs** | tc_cf5f11ac, tc_31115633 |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1059.006](https://attack.mitre.org/techniques/T1059/006/) |


YARA signature `HKTL_Meterpreter_inMemory` matched in DC01's memory dump (citadeldc01.mem) with multiple hits for:
- `metsrv.x64.dll` at 5 distinct memory offsets (0x20a27d43, 0x25de6482, 0x38a5dd43, 0x650ef482, 0x78183d43)
- `ReflectiveLoader` at 15 distinct offsets (0x20a27d52, 0x25d9f3c0, 0x25de6491, 0x26aa4c1d, etc.)
- `WS2_32.dll` (Winsock networking DLL) referenced at 250+ offsets

The ReflectiveLoader string is the hallmark of Metasploit's reflective DLL injection technique, and metsrv.x64.dll is the Meterpreter server DLL. This is corroborated by malfind results showing injected code in spoolsv.exe (PID 3724) with classic Metasploit x64 shellcode prologue (FC 48 89 CE 48 81 EC 00 20 - cld; mov rsi, rcx; sub rsp, 0x2000) and MZ headers injected into executable memory regions with PAGE_EXECUTE_READWRITE protections. The MZ header starting with "MZARUH" is characteristic of Metasploit's reflective loader stub. Multiple independent detection methods (YARA signatures, malfind code injection, and network indicators) all confirm active Meterpreter presence.

**Counter-Analysis (Q-CA8 - AV signature store vs active implant):** The Meterpreter YARA signatures are NOT false positives from AV signature database memory. Evidence: (1) The metsrv.x64.dll and ReflectiveLoader strings cluster at memory offsets that align with each other (e.g., 0x20a27d43 and 0x20a27d52 are 15 bytes apart — matching the internal layout of metsrv.dll where these strings are adjacent), confirming they are part of an intact loaded binary, not isolated signature matches. (2) Malfind independently confirms PAGE_EXECUTE_READWRITE regions in spoolsv.exe (PID 3724) containing MZ headers and Metasploit shellcode bytes — these are in executable process memory, not in an AV engine's signature store. (3) DC01 runs Windows Server 2012 R2 with no effective endpoint protection detected (unlike DESKTOP which has Windows Defender/MsMpEng.exe). (4) The 92.63.197.153/good.exe AV false positive pattern was correctly identified and excluded (f_6e53e8cd) — that FP appeared only in strings/bulk data, never in YARA or malfind.



### 2. [CRITICAL] Meterpreter Shellcode Injection in spoolsv.exe (PID 3724)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T01:22:57+00:00 |
| **Sources** | volatility.malfind, volatility.netscan |
| **Evidence Refs** | tc_31115633, tc_d821a7cf |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1055.003](https://attack.mitre.org/techniques/T1055/003/) |


Volatility malfind identified 4 injected memory regions in spoolsv.exe (PID 3724) with PAGE_EXECUTE_READWRITE protections:

1. VPN 322054520832-322054725631: Contains classic Metasploit x64 shellcode prologue (FC 48 89 CE 48 81 EC 00 20 00 00 - cld; mov rsi, rcx; sub rsp, 0x2000) followed by PEB traversal code (48 31 D2 65 48 8B 52 60 - hash-based API resolution). This is the well-known Metasploit stager shellcode pattern.

2. VPN 322057469952-322057908223: Full MZ PE header injected - a reflectively loaded DLL (107 pages committed)

3. VPN 322055897088-322056130559: MZ header beginning with "MZARUH" - the distinctive Metasploit reflective loader stub (57 pages committed)

4. VPN 322057928704-322058076159: Another MZ PE header (36 pages committed)

spoolsv.exe was also LISTENING on TCP port 62475 (both IPv4 and IPv6), which is not a standard print spooler port. This listening port combined with injected Meterpreter code is consistent with a reverse TCP handler or bind shell. The Print Spooler service is a common process-injection target because it runs as SYSTEM with network capabilities.



### 3. [CRITICAL] Explicit Credential Logon from Malware Staging Server IP 194.61.24.102

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:22:09+00:00 to 2020-09-19T03:22:37+00:00 |
| **Sources** | evtx.windows_system32_winevt_logs_security, bulk.url |
| **Evidence Refs** | tc_4ebc540b, tc_5457ed23 |
| **ATT&CK** | [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1021](https://attack.mitre.org/techniques/T1021/) |


Security Event 4648 recorded on CITADEL-DC01 at 2020-09-19 03:22:09 showing a logon attempt using explicit credentials:
- Subject: C137\CITADEL-DC01$ 
- Source IP: 194.61.24.102:0
- Target: C137\Administrator
- TargetServerName: localhost
- Process: C:\Windows\System32\winlogon.exe (PID 0x9F0)

This IP (194.61.24.102) is the same server that hosted the malware at http://194.61.24.102/coreupdater.exe, confirmed by bulk_extractor URL carving from both DC01 and DESKTOP-SDN1RPT evidence. The Event 4648 occurred approximately 40 seconds after the brute force password attempts from the "kali" workstation (03:21:25-03:21:30), indicating the attacker successfully obtained the Administrator credentials and used them to authenticate via the malware staging server. Additional Event 4648 entries at 03:22:37 show continued explicit credential use from the same IP.



### 4. [CRITICAL] Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:40:49+00:00 to 2020-09-19T03:43:10+00:00 |
| **Sources** | bulk.url, strings.output, volatility.netscan, volatility.pstree |
| **Evidence Refs** | tc_5457ed23, tc_d821a7cf |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/) |


The malicious binary coreupdater.exe was downloaded from http://194.61.24.102/coreupdater.exe and placed at C:\Windows\System32\coreupdater.exe on DC01. Evidence chain:

1. Bulk extractor URL carving from DC01 disk image found multiple references to http://194.61.24.102/ and http://194.61.24.102/coreupdater.exe
2. Same URL found in DESKTOP-SDN1RPT pagefile (bulk.url) indicating the workstation also browsed this server. Edge browser activity data shows "Directory listing for /" at http://194.61.24.102/
3. The process ran as PID 3644 on DC01 with an active C2 connection to 203.78.103.109:443
4. On DESKTOP-SDN1RPT (PID 8324), coreupdater.exe ran at 2020-09-19 03:40:49 and exited at 03:43:10. Windows Defender strings reference indicates a reputation check and "block" action against coreupdater.exe (size 7168 bytes)
5. The file is NOT a legitimate Windows component; "coreupdater" is designed to mimic a system update utility

The binary was present on TWO systems (DC01 and DESKTOP-SDN1RPT), indicating either lateral movement delivery or independent download from the staging server. The attacker used IP 194.61.24.102 for both malware staging and credential authentication (Event 4648).

**Affected Systems:** bulk.url, strings.output, volatility.netscan, volatility.pstree



### 5. [CRITICAL] Anomalous Network Listener on spoolsv.exe Port 62475 - Meterpreter Bind Shell Indicator

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:29:40 |
| **Sources** | volatility.netscan, volatility.dlllist, yara.volatility |
| **Evidence Refs** | tc_26a8e982, tc_cc769d39 |
| **ATT&CK** | [T1571](https://attack.mitre.org/techniques/T1571/), [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |


The Windows Print Spooler service (spoolsv.exe, PID 3724) was found LISTENING on TCP port 62475 on both IPv4 and IPv6 interfaces. This is highly anomalous:

**Network Evidence (Volatility netscan):**
- TCPv4 0.0.0.0:62475 → LISTENING (PID 3724, spoolsv.exe)
- TCPv6 :::62475 → LISTENING (PID 3724, spoolsv.exe)

**Why This Is Anomalous:**
- The Windows Print Spooler service normally listens on standard ports (445 for SMB printing, 135 for RPC). Port 62475 is an ephemeral/high port with no legitimate spooler function.
- This same PID (3724) has confirmed Meterpreter shellcode injected (YARA: HKTL_Meterpreter_inMemory, Volatility malfind: PAGE_EXECUTE_READWRITE with Metasploit shellcode prologue and MZ reflective loader headers).
- A LISTENING socket on a high port in a Meterpreter-injected process is consistent with a bind shell handler or pivot/relay capability, allowing the attacker to establish additional connections to the compromised DC.

**DLL Evidence (Volatility dlllist):**
- spoolsv.exe base module loaded from C:\Windows\System32\spoolsv.exe
- Module timestamp shows 2020-09-19 03:29:40 - this aligns with the post-compromise timeline (brute force at 03:21, credential logon at 03:22, injection at 03:29).



### 6. [CRITICAL] Complete Attack Timeline: External Brute Force to Domain Controller Compromise

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:12:46Z to 2020-09-19T03:43:10 |
| **Sources** | bulk.url, evtx.windows_system32_winevt_logs_security, tsk.filelist, volatility.dlllist, volatility.malfind, volatility.netscan, yara.volatility |
| **Evidence Refs** | tc_26a8e982, tc_7acd68fc, tc_cc769d39, tc_f652cb5a |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |


Reconstructed attack timeline from correlated evidence across memory forensics, event logs, disk forensics, and network artifacts:

**Phase 1 - Reconnaissance/Initial Access (03:12-03:22 UTC, 2020-09-19):**
- 03:12:46: Nmap RDP reconnaissance probe from 194.61.24.102 (cookie="nmap") [Source: Zeek RDP]
- 03:14:46-03:15:07: RDP brute force attack (~100 attempts in 21 seconds, sequential source ports) [Source: Zeek RDP]
- 03:21:25-03:21:30: Brute force password attack from workstation "kali" against \Administrator account (6 failed attempts via NTLM, 1/sec) [Source: Security EVTX Event 4625]
- 03:22:09: Successful explicit credential logon (Event 4648) for C137\Administrator from 194.61.24.102 (Russia, AS41842) via winlogon.exe
- 03:22:37: Additional explicit credential use from same Russian IP

**Phase 2 - Malware Deployment (~03:17-03:29 UTC):**
- 03:17:06: First PE file (coreupdater.exe) transferred over network [Source: Zeek PE, security mitigations disabled, non-standard .lhru section]
- coreupdater.exe placed at C:\Windows\System32\coreupdater.exe on DC01 for masquerading

**Phase 3 - Execution & C2 Establishment (~03:29 UTC):**
- 03:29:40: spoolsv.exe (PID 3724) injected with Meterpreter payload via reflective DLL injection [Source: Volatility dlllist timestamp, malfind, YARA]
- coreupdater.exe (PID 3644) established HTTPS C2 connection to 203.78.103.109:443 (Thailand, AS23884)
- spoolsv.exe opened bind listener on TCP port 62475

**Phase 4 - Lateral Expansion (03:22-03:40 UTC):**
- 03:22:35: RDP lateral movement from DC01 (10.42.85.10) to DESKTOP-SDN1RPT (10.42.85.115) [Source: Zeek RDP]
- 03:33:18: Second PE file transferred (to DESKTOP) [Source: Zeek PE, identical binary attributes]
- 03:40:49: coreupdater.exe deployed and executed on DESKTOP-SDN1RPT (PID 8324)
- 03:43:10: Process terminated — Windows Defender blocked the 7168-byte payload

**Phase 5 - Sustained Access (post-03:29):**
- Meterpreter implant running as SYSTEM in spoolsv.exe with full domain admin privileges
- C2 channel over HTTPS providing ongoing remote access to both systems
- Two persistent ESTABLISHED connections from DESKTOP to 203.78.103.109:443 (PID not resolved — likely via injected code in spoolsv.exe PID 2188 or powershell.exe PID 3316)

**Attacker Infrastructure:**
- 194.61.24.102 (Russia, AS41842): Malware staging and credential authentication
- 203.78.103.109 (Thailand, AS23884): C2 server receiving encrypted HTTPS callbacks

**Kill Chain Assessment (Q-CA9):** This timeline spans 7 ATT&CK kill chain phases (Reconnaissance → Initial Access → Execution → Defense Evasion → Lateral Movement → Discovery → Command & Control) in a temporally coherent sequence corroborated by 7+ independent evidence sources (EVTX, Zeek RDP/PE/Kerberos, Volatility netscan/malfind/YARA, bulk_extractor, disk forensics). The causal and temporal coherence eliminates the possibility that these events are individually benign coincidences.

**Note:** This is a timeline synthesis of individual findings (f_aefe4e49, f_240aa1fe, f_85641e1c, f_726911f5, f_98d81f6c, f_0637f547, f_50a6e547, f_ee80c4fe, f_1faae5a6, f_b2a63ef7, f_8b75483a). Refer to individual findings for detailed evidence.



### 7. [CRITICAL] Active C2 Connections from DESKTOP-SDN1RPT to 203.78.103.109:443

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:40:49+00:00 |
| **Sources** | volatility.netscan, enrichment.iocs, volatility.pstree |
| **Evidence Refs** | tc_f0a2a636, tc_ffe5e358 |
| **ATT&CK** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573.002](https://attack.mitre.org/techniques/T1573/002/) |


DESKTOP-SDN1RPT (IP: 10.42.85.115) maintained TWO simultaneous ESTABLISHED TCP connections to external C2 server 203.78.103.109 on port 443:

1. 10.42.85.115:50875 → 203.78.103.109:443 (ESTABLISHED)
2. 10.42.85.115:50972 → 203.78.103.109:443 (ESTABLISHED)

IP enrichment reveals 203.78.103.109 is located in Thailand (AS23884, Proen Corp Public Company Limited). This is the same C2 IP used by DC01's coreupdater.exe (PID 3644), confirming both systems were compromised by the same threat actor.

**Counter-Analysis Note (PID resolution):** Neither connection has a PID resolved in Volatility netscan (both show PID `-`). This is consistent across many TCP connections in DESKTOP's netscan output, suggesting a memory dump artifact rather than evasion. However, coreupdater.exe (PID 8324) had already exited at capture time (ran 03:40:49 to 03:43:10), and these connections were still ESTABLISHED — indicating the socket handles were inherited or transferred to another process. Combined with malfind evidence of code injection in spoolsv.exe (PID 2188) and powershell.exe (PID 3316), the connections likely belong to one of these injected processes.

**Q-CA3 Assessment:** These connections cannot be legitimate HTTPS traffic. The same IP (203.78.103.109) is connected via coreupdater.exe on DC01 — a confirmed Meterpreter payload. No legitimate cloud service, CDN, or SaaS provider is associated with this Thai IP (AS23884 Proen Corp). The connection exists only during the incident window.

The user ricksanchez was actively logged in on DESKTOP-SDN1RPT at capture time (explorer.exe PID 5896).



### 8. [CRITICAL] Cross-System C2 Infrastructure: Both DC01 and DESKTOP-SDN1RPT Connected to 203.78.103.109:443

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T01:22:57+00:00 |
| **Sources** | volatility.netscan, composite.pcap_correlation, composite.correlation, enrichment.iocs |
| **Evidence Refs** | tc_7fb0a10b, tc_19b5206e |
| **ATT&CK** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573.002](https://attack.mitre.org/techniques/T1573/002/), [T1571](https://attack.mitre.org/techniques/T1571/) |


Cross-system correlation confirms both compromised hosts maintained active C2 connections to the same external server, demonstrating unified attacker control across the environment:

**CITADEL-DC01 (10.42.85.10):**
- 10.42.85.10:62613 → 203.78.103.109:443 (ESTABLISHED, PID 3644 coreupdater.exe)
- Source: volatility.netscan from DC01 memory dump (citadeldc01.mem)
- Confirmed Meterpreter implant via YARA and malfind in spoolsv.exe (PID 3724)

**DESKTOP-SDN1RPT (10.42.85.115):**
- 10.42.85.115:50875 → 203.78.103.109:443 (ESTABLISHED)
- 10.42.85.115:50972 → 203.78.103.109:443 (ESTABLISHED)
- Source: volatility.netscan from DESKTOP memory dump (desktop-sdn1rpt.mem)
- Two simultaneous connections; malfind confirms code injection in spoolsv.exe (PID 2188) and powershell.exe (PID 3316)

**PCAP Corroboration:**
- composite.pcap_correlation confirmed IP matches between PCAP conversations and netscan data for both systems
- PCAP shows SMB (port 445) and RPC (port 135) lateral movement traffic between the two hosts
- Zeek PE analysis captured two identical PE file transfers at 03:17:06 and 03:33:18 — corresponding to coreupdater.exe delivery to each host

**IOC Enrichment:**
- 203.78.103.109: Thailand, AS23884 Proen Corp Public Company Limited
- Port 443 usage blends C2 traffic with legitimate HTTPS

**Convergence Assessment:** Three independent evidence types (memory forensics from two separate hosts, network capture) all confirm the same C2 infrastructure, establishing this as a confirmed cross-system finding with high confidence.



### 9. [HIGH] Brute Force Password Attack from "kali" Workstation Against Administrator Account

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:21:25+00:00 to 2020-09-19T03:21:30+00:00 |
| **Sources** | evtx.windows_system32_winevt_logs_security |
| **Evidence Refs** | tc_bf02ade3 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |


Multiple Security Event 4625 (failed logon) entries recorded on CITADEL-DC01 starting at 2020-09-19 03:21:25 targeting the Administrator account with:
- Source workstation named "kali" (indicating an attacker system running Kali Linux)
- LogonType 3 (network logon) via NtLmSsp/NTLM authentication
- Status 0xC000006D with SubStatus 0xC000006A ("user name is correct but the password is wrong")
- Failed attempts at 03:21:25, 03:21:26, 03:21:27, 03:21:28, 03:21:29, 03:21:30 (rapid-fire, 1 per second)
- Target was the "\Administrator" account (domain admin)

This pattern of rapid consecutive failed logon attempts from a workstation literally named "kali" is definitive evidence of an active brute force password attack against the domain controller's Administrator account from an attacker-controlled system. The attack succeeded shortly after, as evidenced by the Event 4648 at 03:22:09 with explicit credentials for C137\Administrator from IP 194.61.24.102.



### 10. [HIGH] Attacker Infrastructure: Russia-Hosted Staging Server and Thailand-Hosted C2 Server

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:12:46+00:00 to 2020-09-19T05:08:43+00:00 |
| **Sources** | volatility.netscan, bulk.url, bulk.domain |
| **Evidence Refs** | tc_7acd68fc, tc_c2d4ffa4 |
| **ATT&CK** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573.002](https://attack.mitre.org/techniques/T1573/002/) |


IOC enrichment reveals the attacker operated from geographically distributed infrastructure:

1. **194.61.24.102** (Staging/Delivery & Initial Access):
   - Country: Russia, ASN: AS41842 LLC "MEDIA SYSTEMS"
   - Role: Hosted coreupdater.exe malware for download; used as source IP for explicit credential authentication (Event 4648) and RDP brute force attack
   - Confirmed via: bulk.url carving from both systems, EVTX security logs, Zeek RDP logs

2. **203.78.103.109** (Command & Control):
   - Country: Thailand, ASN: AS23884 Proen Corp Public Company Limited
   - Role: Active C2 server over port 443 (HTTPS)
   - Confirmed via: volatility.netscan from both DC01 (PID 3644) and DESKTOP-SDN1RPT (two connections)

**Excluded IOC: 92.63.197.153** — This IP appeared in pagefile strings and bulk.domain but is confirmed as cached Windows Defender AV signature data (embedded in malware definition strings with family names like "!Zonidel.A"). NOT an active attacker IOC for this incident.

The geographic separation (Russia staging, Thailand C2) suggests compartmentalized operations to complicate attribution and takedown.



### 11. [HIGH] Malware Masquerading in System32: coreupdater.exe Deployed as Fake System Binary

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:17:06+00:00 |
| **Sources** | tsk.filelist, volatility.svcscan, ez.shimcache |
| **Evidence Refs** | tc_6a8afdb3, tc_e748751d |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1036.004](https://attack.mitre.org/techniques/T1036/004/) |


The attacker placed coreupdater.exe in C:\Windows\System32\ (inode 87137-128-4 on the DC01 disk image), masquerading as a legitimate Windows system update component. Evidence:

1. **TSK file listing** (tsk.filelist): coreupdater.exe found at Windows/System32/coreupdater.exe (inode 87137) among legitimate Windows binaries
2. **No corresponding Windows service**: Volatility svcscan shows no service registered for coreupdater.exe - it runs as a standalone process, not via the Service Control Manager
3. **No ShimCache entry**: Absence from AppCompatCache suggests the binary was recently placed and may have been executed only via direct invocation or scripted deployment
4. **Not a legitimate Windows component**: "coreupdater" is not a known Microsoft binary; the naming convention mimics legitimate update services (e.g., Windows Update) for stealth

Placing malware in System32 is a classic defense evasion technique - it leverages the trusted directory to avoid scrutiny and may bypass path-based application whitelisting rules. The file was downloaded from 194.61.24.102 (Russia) as confirmed by bulk_extractor URL carving.



### 12. [HIGH] Code Injection in DESKTOP-SDN1RPT spoolsv.exe and powershell.exe

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:24:09+00:00 |
| **Sources** | volatility.malfind, volatility.pstree |
| **Evidence Refs** | tc_46b239b2 |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |


Volatility malfind detected injected executable code in multiple processes on DESKTOP-SDN1RPT:

1. **spoolsv.exe (PID 2188)**: Contains an injected MZ PE header in a memory region with PAGE_EXECUTE_READWRITE protection (36 pages committed). This mirrors the Meterpreter injection pattern found in DC01's spoolsv.exe (PID 3724), where YARA confirmed HKTL_Meterpreter_inMemory signatures. While YARA vadyarascan was not run on DESKTOP-SDN1RPT's memory, the identical injection pattern (MZ header in RWX memory of spoolsv.exe) and the shared C2 infrastructure (203.78.103.109:443) strongly suggest the same Meterpreter payload.

2. **powershell.exe (PID 3316)**: Multiple injected regions:
   - MZ PE header in RWX memory at VPN 1152863633408-1152863780863 (36 pages)
   - Two additional RWX regions with all-zero content (107 pages and 57 pages) — reserved memory for payload staging
   - Two regions containing PNG image data embedded in RWX memory

   PID 3316 was spawned by PID 508 (another powershell.exe, now exited), which itself was spawned by PID 1380 — a process not visible in the process tree. This orphaned parent chain suggests the initial PowerShell was launched by a now-terminated attacker process.

3. **MsMpEng.exe (PID 2404)**: RWX memory region (256 pages) — this is likely a false positive as Windows Defender's antimalware engine legitimately uses RWX memory for signature matching emulation.



### 13. [HIGH] Suspicious PowerShell Execution Chain with Orphaned Parent Process

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2020-09-19T05:08:37+00:00 to 2020-09-19T05:08:43+00:00 |
| **Sources** | volatility.cmdline, volatility.malfind, volatility.pstree |
| **Evidence Refs** | tc_0e733360, tc_46b239b2, tc_502be3e2, tc_eac958ad |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |


A suspicious PowerShell execution chain was identified on DESKTOP-SDN1RPT:

**Chain:** PID 1380 (unknown, not in pstree/pslist) → PID 508 (powershell.exe, exited 05:08:43) → PID 3316 (powershell.exe, running at capture) → PID 728 (conhost.exe)

Key suspicious indicators:
1. **Orphaned parent (PID 1380)**: The initial PowerShell process (PID 508) was spawned by PID 1380 which does not appear in the process tree or pslist output. This parent process either exited before the memory capture or was hidden — consistent with a dropped/injected implant that launched PowerShell then terminated.

2. **Two-stage PowerShell**: PID 508 ran briefly (05:08:37 to 05:08:43) and spawned PID 3316 which remained running. This pattern is common with PowerShell download cradles or encoded command execution that spawns a child PowerShell process.

3. **No command line captured**: Both powershell.exe processes show empty command lines in Volatility cmdline output, which occurs when process parameters were not available in memory — potentially due to deliberate clearing or memory overwrite.

4. **Code injection in child process**: PID 3316 has multiple PAGE_EXECUTE_READWRITE memory regions including an MZ PE header, indicating a DLL was reflectively loaded into this PowerShell process. This is consistent with a Meterpreter or similar implant operating within the PowerShell process.

5. **Session context**: Both PowerShell processes ran in Session 2 (interactive desktop session), matching the ricksanchez user's explorer.exe session.

**Affected Systems:** volatility.cmdline, volatility.malfind, volatility.pstree



### 14. [HIGH] RDP Brute Force Attack from 194.61.24.102 Visible in Network Traffic

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:12:46Z to 2020-09-19T03:49:23Z |
| **Sources** | zeek.rdp |
| **Evidence Refs** | tc_c308ad1f, tc_0dcca340 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


Network packet analysis (Zeek RDP log) reveals a complete RDP brute force attack sequence from external IP 194.61.24.102 targeting domain controller 10.42.85.10 (CITADEL-DC01) on port 3389.

The attack proceeded in three distinct phases:

1. **Nmap Reconnaissance Probe** (2020-09-19 03:12:46 UTC, ts=1600481966): Single connection from 194.61.24.102:38100 to 10.42.85.10:3389 with cookie="nmap", security_protocol="HYBRID_EX". This identifies the attacker's use of Nmap for RDP service discovery.

2. **Rapid Brute Force** (03:14:46-03:15:07 UTC, ts=1600482086-1600482107): Approximately 100 rapid RDP connection attempts from sequential source ports (40044-40234), all with cookie="Administrator", security_protocol="HYBRID", at approximately 200ms intervals. This represents automated credential guessing against the Administrator account.

3. **Follow-up Connections** (03:15:28-03:49:23 UTC): Two slower attempts at ts=1600482128 and ts=1600482156, followed by a final connection at ts=1600484163. The slower cadence suggests possible manual interaction after the brute force phase succeeded.

This PCAP evidence independently corroborates the existing Windows Event Log finding (f_240aa1fe) of RDP brute force from the same IP. The network data provides complementary detail: the nmap probe cookie identifies the reconnaissance tool, and the sequential source port pattern confirms automated tooling. The HYBRID security protocol indicates NLA (Network Level Authentication) was enforced, meaning the attacker required valid credentials to establish a session.



### 15. [HIGH] Suspicious PE Binary Transfer Over Network (coreupdater.exe)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:17:06Z to 2020-09-19T03:33:18Z |
| **Sources** | zeek.pe, tcpflow.streams |
| **Evidence Refs** | tc_425f6990, tc_8793642f |
| **ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |


Zeek PE analysis detected two identical portable executable files transferred over the network at 2020-09-19 03:17:06 UTC (ts=1600482246) and 03:33:18 UTC (ts=1600483198). Both PE files share identical suspicious characteristics:

**Binary Attributes:**
- Architecture: AMD64, subsystem: WINDOWS_GUI
- Compile timestamp: 2010-04-15 (1271282813.0) — likely falsified given the 2020 attack timeline
- uses_aslr: false, uses_dep: false, uses_code_integrity: false — all security mitigations disabled
- uses_seh: true
- No certificate table, no debug data, no export table
- Section names: .text, .rdata, **.lhru** — the .lhru section name is non-standard and characteristic of custom/malicious tooling. Standard PE section names are .text, .data, .rdata, .bss, .rsrc, .reloc.

**Timing Context:**
The first PE transfer (03:17:06) occurs approximately 2 minutes after the RDP brute force attack on CITADEL-DC01 succeeded (~03:15 UTC). The second transfer (03:33:18) occurs approximately 11 minutes after the first lateral RDP connection from DC01 to DESKTOP-SDN1RPT (03:22:35 UTC).

These PE files correspond to coreupdater.exe, which was identified in prior host analysis as a Meterpreter reverse shell payload deployed via the Metasploit framework. The network evidence confirms the binary was actively transferred to both the domain controller and workstation during the attack, corroborating host-based findings of file creation and execution.



### 16. [HIGH] Lateral Movement via RDP from Domain Controller to Workstation

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:22:35Z to 2020-09-19T03:22:35Z |
| **Sources** | zeek.rdp, zeek.kerberos |
| **Evidence Refs** | tc_0a9ce18b, tc_2733c2d9 |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |


Zeek RDP log captures a lateral movement session from the domain controller CITADEL-DC01 (10.42.85.10) to workstation DESKTOP-SDN1RPT (10.42.85.115) via RDP at 2020-09-19 03:22:35 UTC (ts=1600482955).

**Network Connection Details:**
- Source: 10.42.85.10:62514 (CITADEL-DC01)
- Destination: 10.42.85.115:3389 (DESKTOP-SDN1RPT)
- Direction: Internal — DC → workstation

**Attack Chain Context:**
This lateral movement occurs in a clear temporal sequence within the PCAP:
1. 03:12:46 — Nmap RDP reconnaissance probe from 194.61.24.102
2. 03:14:46-03:15:07 — RDP brute force attack (~100 attempts in 21 seconds)
3. 03:17:06 — First PE file (coreupdater.exe) transferred
4. **03:22:35 — This RDP lateral movement from DC01 → DESKTOP**
5. 03:33:18 — Second PE file transferred (to DESKTOP)

The corresponding Kerberos authentication for this lateral movement is visible in zeek.kerberos: Administrator/C137.LOCAL obtained TGS tickets for host/desktop-sdn1rpt, ldap/CITADEL-DC01.C137.local, cifs, and ProtectedStorage/CITADEL-DC01 starting at ts=1600482984 (03:16:24 UTC). The domain controller initiating an outbound RDP connection to a workstation is inherently suspicious — domain controllers should rarely if ever be used as RDP client machines.



### 17. [MEDIUM] Active Directory Database (NTDS.dit) and Credential Hives Collected for Extraction

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:22:38+00:00 |
| **Sources** | DC01-ProtectedFiles |
| **Evidence Refs** | tc_1c56dd18 |
| **ATT&CK** | [T1003.003](https://attack.mitre.org/techniques/T1003/003/), [T1003.002](https://attack.mitre.org/techniques/T1003/002/) |


The DC01-ProtectedFiles evidence archive contains a complete set of Active Directory credential databases and registry hives:

1. ntds.dit (20.0 MB) - AD database containing all domain user password hashes, Kerberos keys
2. SAM (256 KB) - Local account password hashes
3. SECURITY (256 KB) - LSA secrets, cached domain credentials
4. system (12.2 MB) - SYSTEM registry hive (required for SYSKEY/Boot Key decryption)
5. Administrator NTUSER.DAT, DPAPI master keys, and RSA crypto keys

**Context:** These files were collected as part of the forensic evidence package (alongside disk images and memory dumps from both systems). The structured naming convention ("DC01-ProtectedFiles") and inclusion alongside other forensic artifacts strongly suggests investigator evidence collection rather than attacker staging.

**Capability Assessment:** The attacker had Domain Administrator credentials and an active Meterpreter implant on DC01, giving full capability to extract NTDS.dit. However, NO credential dumping tools (ntdsutil, vssadmin shadow copy, mimikatz, secretsdump) were found in shimcache, amcache, prefetch, or process memory on DC01. PCAP analysis also confirmed DRSGetNCChanges (DCSync) was NOT observed in the Zeek DCE/RPC logs.

**Assessment:** While the attacker had the capability, no evidence confirms actual credential extraction occurred during this incident.



### 18. [MEDIUM] DESKTOP-SDN1RPT Targeted with coreupdater.exe - Blocked by Windows Defender

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:40:49 to 2020-09-19T03:43:10 |
| **Sources** | volatility.pstree, strings.output, bulk.url |
| **Evidence Refs** | tc_7b14e699, tc_5ea717ae |
| **ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |


The attacker also deployed coreupdater.exe to DESKTOP-SDN1RPT (10.42.85.115), a workstation in the C137 domain:

**Evidence from DESKTOP-SDN1RPT memory dump:**
- coreupdater.exe (PID 8324) ran at 2020-09-19 03:40:49 and exited at 03:43:10 (approximately 2.5 minutes of execution)
- Process tree shows coreupdater.exe spawned as a standalone process, then terminated
- No active C2 connection found in DESKTOP-SDN1RPT netscan (process had already exited)

**Windows Defender Detection (from strings):**
- Windows Defender performed a reputation check and "block" action on coreupdater.exe
- File size recorded as 7168 bytes - matches the small stager/dropper size typical of Metasploit payloads
- The JSON entry shows: "isFileSupported", "path":"C:\\Windows\\System32\\coreupdater.exe", "size":"7168", followed by "checkReputation" and "block"

**Delivery Evidence:**
- http://194.61.24.102/coreupdater.exe URL found in DESKTOP-SDN1RPT pagefile via bulk_extractor
- Edge browser browsing history shows the user visited http://194.61.24.102/ (directory listing viewed)

**Contrast with DC01:** Unlike DESKTOP-SDN1RPT where Defender blocked the malware, DC01 (Windows Server 2012 R2) had no effective endpoint protection, allowing the malware to persist and maintain C2.



### 19. [MEDIUM] DESKTOP-SDN1RPT Credential Hives and DPAPI Keys Collected

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:24:07+00:00 |
| **Sources** | clamav.scan, hashdeep.hashes |
| **Evidence Refs** | tc_edacb32d, tc_28856b1d |
| **ATT&CK** | [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1555.004](https://attack.mitre.org/techniques/T1555/004/) |


The DESKTOP-SDN1RPT-Protected Files evidence archive contains credential material from the workstation (SID: S-1-5-21-2232410529-1445159330-2725690660):

**Registry Hives:** SAM, SECURITY, system, software
**User Profiles (4 users):** Administrator, ricksanchez, mortysmith, Admin — each with NTUSER.DAT, DPAPI master keys, and CREDHIST files. Domain Backup Keys ("BK-C137") present in each user's DPAPI Protect directory.

**Context:** Like the DC01-ProtectedFiles, this archive was collected as part of the forensic evidence package. The structured naming and inclusion alongside disk images/memory dumps indicates investigator collection, not attacker staging.

**Assessment:** Downgraded from high to medium. These credential stores represent the potential impact of the compromise (what the attacker COULD access), not confirmed attacker activity. ClamAV scanning found no embedded malware in these files.



### 20. [MEDIUM] PCAP Traffic Profile: Encrypted Attack Channels Evaded IDS Detection

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T21:58:07Z to 2020-09-19T05:38:57Z |
| **Sources** | pcap.summary, suricata.alerts, pcap.beaconing, pcap.tunneling, pcap.tls, pcap.http, zeek.dns |
| **Evidence Refs** | tc_4bc2a3f8, tc_302ade9e |
| **ATT&CK** | [T1573](https://attack.mitre.org/techniques/T1573/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |


Analysis of the full PCAP capture (411K packets, 197MB, spanning 2020-09-18 21:58:07 to 2020-09-19 05:38:57 UTC) reveals that the attacker's operational traffic was conducted entirely over encrypted protocols, resulting in zero Suricata IDS alerts despite an active compromise.

**Traffic Profile Summary:**
- Total: 411,797 packets across ~7.7 hours
- Dominant protocols: TCP (9,602 frames in first 10K sample), TLS (1,518 frames), SMB2 (179), LDAP (97), DCE/RPC (96), Kerberos (46), DNS (159)
- HTTP: Only 18 frames, all OCSP certificate validation traffic to ocsp.digicert.com and ocsp.msocsp.com (Microsoft-CryptoAPI/10.0 user agent)
- No SMTP, no FTP, no plaintext credential transmission

**IDS Evasion Assessment:**
Suricata with the Emerging Threats ruleset produced 0 alerts. The attacker used only encrypted or protocol-native channels: RDP (encrypted via TLS/HYBRID), SMB2 (for file transfers and lateral movement), Kerberos (for authentication), and DCE/RPC (for directory services). No custom C2 traffic to 203.78.103.109 appears in this capture — the Meterpreter C2 channel was either not active during this capture window or routed through a different network path.

**DNS Assessment:**
- 1,813 DNS records analyzed, all resolving to legitimate Microsoft domains and c137.local (the internal AD domain)
- DNS tunneling analysis flagged 4 domains (microsoft.com, msn.com, c137.local, akamaized.net) but all are false positives — low entropy (3.70-4.29), short label lengths, and all are expected Microsoft service domains
- No evidence of DNS-based exfiltration or covert channels

**Beaconing Assessment:**
- 216 destination IPs analyzed, 0 beaconing patterns detected
- No periodic callback patterns consistent with C2 heartbeats

**TLS Assessment:**
- All TLS connections from 10.42.85.115 are to legitimate Microsoft services (settings-win.data.microsoft.com, watson.telemetry.microsoft.com, www.bing.com, go.microsoft.com, etc.)
- All certificates issued by legitimate Microsoft and Akamai CAs
- No self-signed or suspicious certificates observed

**Key Insight:** The absence of IDS alerts does not indicate the absence of malicious activity. The attack was conducted using standard Windows protocols (RDP, SMB, Kerberos, DCE/RPC) that blend with normal enterprise traffic. This technique is consistent with "living off the land" methodology where attackers leverage built-in administrative tools and protocols to avoid signature-based detection.



### 21. [MEDIUM] Post-Compromise Active Directory Enumeration via DCE/RPC and Kerberos

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-19T03:16:24Z to 2020-09-19T04:49:53Z |
| **Sources** | zeek.kerberos, zeek.dce_rpc, zeek.smb_files |
| **Evidence Refs** | tc_2733c2d9, tc_2dc1b371, tc_6aa68f12 |
| **ATT&CK** | [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |


Network protocol analysis reveals post-compromise Active Directory enumeration activity originating from DESKTOP-SDN1RPT (10.42.85.115) against CITADEL-DC01 (10.42.85.10) following the successful RDP brute force attack.

**Kerberos Authentication Sequence (zeek.kerberos):**
After the RDP brute force succeeded at ~03:15 UTC, the compromised Administrator account was used to request Kerberos TGS tickets for multiple services:
- host/desktop-sdn1rpt (workstation access)
- ldap/CITADEL-DC01.C137.local (LDAP directory queries)
- cifs (SMB file share access)
- ProtectedStorage/CITADEL-DC01 (credential storage)
All requests from client Administrator/C137.LOCAL at ts=1600482984 (~03:16:24 UTC), using aes256-cts-hmac-sha1-96 cipher.

**DCE/RPC Operations (zeek.dce_rpc):**
209 DCE/RPC records show extensive directory service interaction:
- **DRSUAPI** (DRSBind, DRSCrackNames, DRSUnbind) on port 49155: Directory replication service operations used for AD name resolution. CRITICALLY: DRSGetNCChanges was NOT observed — no DCSync attack occurred in the PCAP capture window.
- **lsarpc** (LsarLookupSids3): SID-to-name resolution, consistent with account enumeration
- **samr** (SamrQuerySecurityObject): Security descriptor queries against SAM database via \\pipe\\lsass
- **epmapper** (ept_map) on port 135: Endpoint mapper queries to discover RPC service ports

**SMB File Access (zeek.smb_files):**
Post-compromise SMB access to:
- \\\\CITADEL-DC01\\NETLOGON at ts=1600482984 (03:16:24 UTC)
- \\\\CITADEL-DC01\\FileShare at ts=1600488593 (~04:49:53 UTC)
- \\\\CITADEL-DC01\\sysvol (Group Policy objects access throughout)

**Counter-Analysis Assessment (Q-CA5):** Individual DCE/RPC operations (DRSBind, DRSCrackNames, lsarpc, samr) CAN represent normal Active Directory domain operations. In isolation, this finding would be weak. However, the temporal context is critical: these operations occur immediately after confirmed attacker credential compromise (03:15-03:22 UTC), using the same Administrator account that was brute-forced. Within the broader kill chain (Nmap recon → brute force → credential logon → malware delivery → injection → lateral movement), this activity fits naturally as the enumeration/discovery phase. The ProtectedStorage TGS request is particularly notable as it targets credential storage. Removing this finding would leave a gap in the kill chain between credential compromise and lateral movement/malware deployment. Severity and confidence remain medium/inference as the individual operations are ambiguous, but the kill chain context weighs against dismissal.



### 22. [LOW] DESKTOP-SDN1RPT SMB Connection to Compromised Domain Controller DC01

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:24:10+00:00 |
| **Sources** | volatility.netscan |
| **Evidence Refs** | tc_f0a2a636 |
| **ATT&CK** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |


Volatility netscan from DESKTOP-SDN1RPT memory shows an ESTABLISHED SMB connection from the workstation to the domain controller:

- 10.42.85.115:50957 → 10.42.85.10:445 (ESTABLISHED, System PID 4)

While both systems are confirmed compromised, SMB connections between a domain-joined workstation and its DC are routine for Group Policy, authentication, NETLOGON, and SYSVOL access. Zeek SMB file analysis confirms access patterns to \\CITADEL-DC01\NETLOGON, \\CITADEL-DC01\sysvol, and \\CITADEL-DC01\FileShare — standard domain operations.

This connection alone does not constitute evidence of attacker lateral movement. The confirmed lateral movement occurred via RDP (Zeek RDP log showing DC01→DESKTOP at 03:22:35 UTC, finding f_1faae5a6), not SMB. Downgraded from medium to low as the SMB connection is expected in a domain environment.



### 23. [LOW] Hidden Processes on DESKTOP-SDN1RPT: psscan vs pslist Discrepancy (6 PIDs)

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:24:07+00:00 |
| **Sources** | composite.defense_evasion, composite.suspicious_processes, volatility.psscan |
| **Evidence Refs** | tc_fbdf5588, tc_9ced7ac8 |
| **ATT&CK** | [T1014](https://attack.mitre.org/techniques/T1014/) |


Cross-referencing psscan (pool-tag scan) against pslist (linked-list walk) on DESKTOP-SDN1RPT reveals 6 process IDs present only in psscan, indicating they were unlinked from the active process list:

**Hidden PIDs:**
- PID 1: Unknown process (no name recovered). PID 1 is not a standard Windows PID (System is PID 4). Anomaly score: 0.
- PID 904: Unknown process. Anomaly score: 0.
- PID 1172: Unknown process. Anomaly score: 0.
- PID 1556: Unknown process. Anomaly score: 0.
- PID 3388: Unknown process. Anomaly score: 0.
- PID 3796: Unknown process. Anomaly score: 0.

**Assessment:** These PIDs were found ONLY on DESKTOP-SDN1RPT. No hidden processes were detected on DC01. All 6 have anomaly_score 0 and no malfind hits, network connections, or command line data recovered. The most likely explanations are:
1. **Normal process termination**: Windows can deallocate process structures from the linked list before pool memory is reclaimed, creating temporary psscan-only entries
2. **Rootkit activity**: Process hiding via DKOM (Direct Kernel Object Manipulation) unlinking from the EPROCESS list

Given that: (a) none of the hidden PIDs had any associated behavioral indicators (no injected code, no network connections, no suspicious parent-child relationships), (b) the known attack tools (Meterpreter, coreupdater.exe) remained visible in pslist, and (c) no rootkit modules were detected in modscan vs modules analysis — the hidden processes are most likely artifacts of normal process termination rather than active rootkit concealment.

**No log clearing or timestomping** was detected on either system (composite.defense_evasion), further suggesting the attacker did not employ kernel-level evasion techniques.



### 24. [INFO] No Evidence of Data Exfiltration or Staging Despite Full Domain Compromise

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | composite.exfil, composite.file_staging, pcap.summary, pcap.beaconing, pcap.tunneling |
| **Evidence Refs** | tc_19b5206e, tc_9ced7ac8 |
| **ATT&CK** | [T1041](https://attack.mitre.org/techniques/T1041/), [T1567](https://attack.mitre.org/techniques/T1567/) |


Cross-system analysis of exfiltration and staging indicators found NO evidence of data exfiltration, despite the attacker having Domain Administrator access to both DC01 and DESKTOP-SDN1RPT:

**Exfiltration Analysis (composite.exfil):**
- 10 indicator windows examined — ALL determined to be false positives
- References to mega.nz, dropbox.com, pastebin.com, catbox.moe, and discord.com were all found in pagefile content containing cached Windows Defender/AV signature data
- Context strings included AV signature names ("!Zonidel.A", "Exploit:O", "Ransom:Win64/Anatova") confirming these are from antimalware definition databases, not user browsing or attacker tool usage
- No actual uploads or file transfers to cloud storage services detected

**File Staging Analysis (composite.file_staging):**
- 61 windows examined — ALL legitimate Windows system files
- Files identified had Archive attribute set (.dll, .cab, NativeImages) in standard Windows directories
- No suspicious archives created in temporary directories, user profiles, or other staging locations
- No recently created .zip, .rar, .7z, or .tar files in anomalous locations

**Network Exfiltration:**
- PCAP analysis (411K packets, 197MB) showed no outbound data transfers to suspicious destinations
- DNS tunneling analysis: 0 actual indicators (4 false positives on microsoft.com, msn.com, c137.local, akamaized.net)
- Beaconing analysis: 0 patterns detected across 216 destination IPs
- All TLS connections from DESKTOP-SDN1RPT were to legitimate Microsoft services

**Assessment:** The attacker achieved full domain compromise but the evidence suggests either: (a) exfiltration had not yet occurred at the time of evidence collection, (b) exfiltration occurred via a different network path not captured in the PCAP, or (c) the attacker's objective was persistent access rather than data theft. The NTDS.dit and credential hives were accessible but no evidence shows they were packaged for exfiltration.



### 25. [INFO] 92.63.197.153/good.exe Is Cached AV Signature Data, Not Active Attacker IOC

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | strings.output, bulk.domain, composite.exfil |
| **Evidence Refs** | tc_9ced7ac8 |


Investigation question Q6 addressed: The IP 92.63.197.153 and associated URL path "/good.exe" found in DESKTOP-SDN1RPT evidence is NOT an active attacker indicator for this incident.

**Evidence Analysis:**
- 92.63.197.153 appears ONLY in strings.output and bulk.domain sources from DESKTOP-SDN1RPT's pagefile
- Every occurrence is embedded within Windows Defender/antimalware signature pattern strings containing malware family names: "!Zonidel.A", "Exploit:O", "Ransom:Win64/Anatova", "Trojan:Win32/", etc.
- The string format and surrounding context match cached AV definition data, not browser history, download logs, or process execution evidence
- NO references to 92.63.197.153 found in: volatility.netscan (no network connections), EVTX logs, MFT timestamps, browser history, or PCAP capture
- The IP does NOT appear in DC01 evidence at all

**Conclusion:** This IP address was present in the pagefile solely because Windows Defender's malware signature database contained it as a known malicious indicator. It represents AV threat intelligence data cached in memory/pagefile, not evidence of the attacker using this IP in this incident. It should be excluded from the IOC list for this case.



### 26. [INFO] No Anti-Forensics or Evidence Tampering Detected Across Either System

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | composite.defense_evasion, composite.recovery, composite.execution, ez.mft |
| **Evidence Refs** | tc_cac32385, tc_9ced7ac8 |


Comprehensive anti-forensics analysis across both compromised systems found zero indicators of evidence destruction or tampering:

**Log Clearing:** No Windows Event Log clearing events (Event IDs 104, 1102) detected on DC01 or DESKTOP-SDN1RPT. Security, System, and PowerShell logs remained intact.

**Timestomping:** No $STANDARD_INFORMATION vs $FILE_NAME timestamp discrepancies detected in MFT analysis (detect_timestomping). coreupdater.exe MFT entry (87137) shows consistent timestamps.

**Secure Delete Tools:** No evidence of execution of secure delete utilities (sdelete, cipher /w, shred) in shimcache, amcache, prefetch, or process memory.

**File Recovery:** 1,968 deleted files detected across the DC01 disk image, but all appear to be normal Windows operational deletions (temp files, logs, updates). No pattern of selective evidence destruction.

**Credential Dumping Tool Artifacts:** Search for ntdsutil, vssadmin (shadow copy), mimikatz, secretsdump, and dcsync across all indexed sources (excluding raw strings/bulk data) returned ZERO results for actual tool execution. While the attacker had Domain Admin access and the capability to dump credentials, no tool artifacts were recovered. Note: DCSync was specifically NOT observed in PCAP (DRSGetNCChanges not present in Zeek DCE/RPC logs).

**Assessment:** The absence of anti-forensics suggests either: (a) the attacker prioritized operational speed over forensic countermeasures, (b) the attack was interrupted before cleanup could occur, or (c) the Meterpreter-in-memory approach was itself the anti-forensics strategy — keeping the primary implant in process memory rather than on disk.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Port | `TCP 62475` |  | Meterpreter Shellcode Injection in spoolsv.exe (PID 3724) |
| External IP | `194.61.24.102` | Russia, AS41842 LLC "MEDIA SYSTEMS" | Brute Force Password Attack from "kali" Workstation Against Administrator Accoun |
| Port | `TCP 0` |  | Explicit Credential Logon from Malware Staging Server IP 194.61.24.102 |
| External IP | `203.78.103.109` | Thailand, AS23884 Proen Corp Public Company Limited. | Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure |
| Port | `TCP 443` |  | Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure |
| External IP | `92.63.197.153` |  | Attacker Infrastructure: Russia-Hosted Staging Server and Thailand-Hosted C2 Ser |
| Internal IP | `10.42.85.115` |  | DESKTOP-SDN1RPT Targeted with coreupdater.exe - Blocked by Windows Defender |
| Internal IP | `10.42.85.10` |  | Complete Attack Timeline: External Brute Force to Domain Controller Compromise |
| Port | `TCP 50875` |  | Active C2 Connections from DESKTOP-SDN1RPT to 203.78.103.109:443 |
| Port | `TCP 50972` |  | Active C2 Connections from DESKTOP-SDN1RPT to 203.78.103.109:443 |
| Port | `TCP 38100` |  | RDP Brute Force Attack from 194.61.24.102 Visible in Network Traffic |
| Port | `TCP 3389` |  | RDP Brute Force Attack from 194.61.24.102 Visible in Network Traffic |
| Port | `TCP 62514` |  | Lateral Movement via RDP from Domain Controller to Workstation |
| Port | `TCP 49155` |  | Post-Compromise Active Directory Enumeration via DCE/RPC and Kerberos |
| Port | `TCP 135` |  | Post-Compromise Active Directory Enumeration via DCE/RPC and Kerberos |
| Port | `TCP 62613` |  | Cross-System C2 Infrastructure: Both DC01 and DESKTOP-SDN1RPT Connected to 203.7 |
| Port | `TCP 445` |  | Cross-System C2 Infrastructure: Both DC01 and DESKTOP-SDN1RPT Connected to 203.7 |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Windows\System32\winlogon.exe` |  | Explicit Credential Logon from Malware Staging Server IP 194.61.24.102 |
| Path | `C:\Windows\System32\coreupdater.exe` |  | Malware Delivery via coreupdater.exe Downloaded from Attacker Infrastructure |
| Path | `C:\Windows\System32\` |  | Malware Masquerading in System32: coreupdater.exe Deployed as Fake System Binary |
| Path | `/System32/coreupdater.exe` |  | Malware Masquerading in System32: coreupdater.exe Deployed as Fake System Binary |
| Path | `C:\Windows\System32\spoolsv.exe` |  | Anomalous Network Listener on spoolsv.exe Port 62475 - Meterpreter Bind Shell In |





---

## Appendix C: MITRE ATT&CK Coverage

25 techniques identified across findings.


**Kill Chain Coverage:** Resource Development (1) > Initial Access (1) > Execution (2) > Persistence (1) > Privilege Escalation (3) > Defense Evasion (6) > Credential Access (4) > Discovery (2) > Lateral Movement (3) > Command and Control (5) > Exfiltration (2)


### Resource Development

| Technique | Name | Findings |
|-----------|------|----------|
| [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Virtual Private Server | Attacker Infrastructure: Russia-Hosted Staging... |


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Explicit Credential Logon from Malware Staging...; Complete Attack Timeline: External Brute Force...; Lateral Movement via RDP from Domain... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | DESKTOP-SDN1RPT Targeted with coreupdater.exe...; Code Injection in DESKTOP-SDN1RPT spoolsv.exe...; Suspicious PowerShell Execution Chain with... |
| [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Python | Meterpreter (Metasploit) Implant Detected in... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Explicit Credential Logon from Malware Staging...; Complete Attack Timeline: External Brute Force...; Lateral Movement via RDP from Domain... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Meterpreter (Metasploit) Implant Detected in...; Meterpreter Shellcode Injection in spoolsv.exe...; Anomalous Network Listener on spoolsv.exe Port...; Complete Attack Timeline: External Brute Force...; Code Injection in DESKTOP-SDN1RPT spoolsv.exe...; Suspicious PowerShell Execution Chain with... |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | Thread Execution Hijacking | Meterpreter Shellcode Injection in spoolsv.exe... |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Explicit Credential Logon from Malware Staging...; Complete Attack Timeline: External Brute Force...; Lateral Movement via RDP from Domain... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1014](https://attack.mitre.org/techniques/T1014/) | Rootkit | Hidden Processes on DESKTOP-SDN1RPT: psscan vs... |
| [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Masquerade Task or Service | Malware Masquerading in System32:... |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Resource Name or Location | Malware Delivery via coreupdater.exe...; Malware Masquerading in System32:...; Complete Attack Timeline: External Brute Force...; Suspicious PE Binary Transfer Over Network... |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Meterpreter (Metasploit) Implant Detected in...; Meterpreter Shellcode Injection in spoolsv.exe...; Anomalous Network Listener on spoolsv.exe Port...; Complete Attack Timeline: External Brute Force...; Code Injection in DESKTOP-SDN1RPT spoolsv.exe...; Suspicious PowerShell Execution Chain with... |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | Thread Execution Hijacking | Meterpreter Shellcode Injection in spoolsv.exe... |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Explicit Credential Logon from Malware Staging...; Complete Attack Timeline: External Brute Force...; Lateral Movement via RDP from Domain... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Active Directory Database (NTDS.dit) and...; DESKTOP-SDN1RPT Credential Hives and DPAPI... |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | Active Directory Database (NTDS.dit) and... |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Brute Force Password Attack from "kali"...; Complete Attack Timeline: External Brute Force...; RDP Brute Force Attack from 194.61.24.102... |
| [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | Windows Credential Manager | DESKTOP-SDN1RPT Credential Hives and DPAPI... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Post-Compromise Active Directory Enumeration... |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Post-Compromise Active Directory Enumeration... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Explicit Credential Logon from Malware Staging... |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | RDP Brute Force Attack from 194.61.24.102...; Lateral Movement via RDP from Domain... |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | DESKTOP-SDN1RPT SMB Connection to Compromised...; Post-Compromise Active Directory Enumeration... |


### Command and Control

| Technique | Name | Findings |
|-----------|------|----------|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | Malware Delivery via coreupdater.exe...; Attacker Infrastructure: Russia-Hosted Staging...; Complete Attack Timeline: External Brute Force...; Active C2 Connections from DESKTOP-SDN1RPT to...; PCAP Traffic Profile: Encrypted Attack...; Cross-System C2 Infrastructure: Both DC01 and... |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Malware Delivery via coreupdater.exe...; DESKTOP-SDN1RPT Targeted with coreupdater.exe...; Complete Attack Timeline: External Brute Force...; Suspicious PE Binary Transfer Over Network... |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | Anomalous Network Listener on spoolsv.exe Port...; Cross-System C2 Infrastructure: Both DC01 and... |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | PCAP Traffic Profile: Encrypted Attack... |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Asymmetric Cryptography | Attacker Infrastructure: Russia-Hosted Staging...; Active C2 Connections from DESKTOP-SDN1RPT to...; Cross-System C2 Infrastructure: Both DC01 and... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | No Evidence of Data Exfiltration or Staging... |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | No Evidence of Data Exfiltration or Staging... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 516 |
| Findings submitted | 26 |
| Confirmed | 19 |
| Inferences | 7 |
| Input tokens | 56.8K |
| Output tokens | 147.4K |
| Total tokens | 204.2K |
| Audit log | /home/mulder/.mulder/cases/szechuan.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 56.8K | 147.4K | 204.2K |




<details>
<summary>Evidence Sources (118)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 10 |
| volatility.pslist | volatility3 | 41 |
| tsk.filelist | sleuthkit | 114999 |
| tsk.filelist.p1 | sleuthkit | 166 |
| volatility.pstree | volatility3 | 41 |
| volatility.cmdline | volatility3 | 41 |
| yara.memory | yara | 350 |
| volatility.netscan | volatility3 | 19686 |
| volatility.malfind | volatility3 | 16 |
| volatility.psscan | volatility3 | 73 |
| volatility.dlllist | volatility3 | 2017 |
| strings.output | strings | 937655 |
| volatility.pslist | volatility3 | 96 |
| bulk.domain | bulk_extractor | 177674 |
| volatility.svcscan | volatility3 | 886 |
| bulk.email | bulk_extractor | 730 |
| bulk.ether | bulk_extractor | 8 |
| bulk.ip | bulk_extractor | 31 |
| bulk.packets | bulk_extractor | 328 |
| bulk.rfc822 | bulk_extractor | 223 |
| bulk.tcp | bulk_extractor | 16 |
| bulk.url | bulk_extractor | 184316 |
| volatility.pstree | volatility3 | 95 |
| bulk.domain | bulk_extractor | 8421 |
| bulk.email | bulk_extractor | 307 |
| bulk.url_facebook-address | bulk_extractor | 6 |
| bulk.url_searches | bulk_extractor | 8 |
| bulk.url_services | bulk_extractor | 828 |
| bulk.ether | bulk_extractor | 9 |
| bulk.rfc822 | bulk_extractor | 230 |
| bulk.url | bulk_extractor | 16254 |
| bulk.url_facebook-address | bulk_extractor | 7 |
| bulk.url_searches | bulk_extractor | 43 |
| bulk.url_services | bulk_extractor | 2198 |
| volatility.cmdline | volatility3 | 96 |
| chainsaw.hunt | chainsaw | 2 |
| ez.amcache | eztools | 4 |
| ez.mft | eztools | 111852 |
| ez.shimcache | eztools | 282 |
| registry.system | regripper | 106 |
| strings.output | strings | 51906 |
| evtx.manifest | evtx-extract | 105 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 25 |
| registry.system | regripper | 8 |
| registry.system | regripper | 8 |
| registry.system | regripper | 29966 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 4936 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| volatility.netscan | volatility3 | 116 |
| volatility.malfind | volatility3 | 8 |
| evtx.windows_system32_winevt_logs_security | eztools | 5073 |
| volatility.psscan | volatility3 | 169 |
| evtx.windows_system32_winevt_logs_active-directory-web-services | eztools | 65 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 150 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 150 |
| volatility.dlllist | volatility3 | 1428 |
| composite.persistence | composite | 2633 |
| volatility.svcscan | volatility3 | 43222 |
| exiftool.metadata | exiftool | 2 |
| hashdeep.hashes | hashdeep | 43 |
| clamav.scan | clamav | 38 |
| yara.memory | yara | 350 |
| composite.defense_evasion | composite | 38 |
| yara.volatility | yara | 35 |
| enrichment.iocs | enrichment | 34 |
| composite.persistence | composite | 9383 |
| suricata.alerts | suricata | 5 |
| pcap.summary | tshark | 85 |
| pcap.conversations | tshark | 143 |
| pcap.dns | tshark | 2 |
| pcap.http | tshark | 19 |
| pcap.smtp | tshark | 2 |
| pcap.tls | tshark | 109 |
| pcap.beaconing | tshark | 5 |
| pcap.tunneling | tshark | 17 |
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
| tcpflow.streams | tcpflow | 433354 |
| tcpxtract.carved | tcpxtract | 432 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.pcap_correlation | composite | 142 |
| composite.lateral_movement | composite | 30 |
| composite.persistence | composite | 9383 |
| composite.exfil | composite | 343 |
| composite.file_staging | composite | 2312 |
| composite.suspicious_processes | composite | 128 |
| composite.timeline | composite | 160 |
| composite.defense_evasion | composite | 38 |
| composite.execution | composite | 144 |
| composite.recovery | composite | 7 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
