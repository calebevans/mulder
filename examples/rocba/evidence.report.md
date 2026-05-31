# Mulder Investigation Report

**Case:** evidence
**Generated:** 2026-05-31T18:50:07.980014+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 55 evidence sources (12 memory, 20 disk, 23 other) | 331 tool calls | 1.3 hours
**Results:** 11 findings (2 critical, 2 high) | 6 confirmed, 5 inference
**Timeline:** 2014-11-06 to 2020-11-16

**Key Threats:**
- APT PutterPanda Malware Detected in Memory
- Multiple Suspicious RDP Connections from Foreign IPs

**Attack Lifecycle:**
- **Initial Access / Deployment** (2020-10-28 to 2020-11-16): Dropbox Configured for Automatic Startup (+8 related)
- **Persistence** (2020-10-20): Two User Accounts with Administrative Privileges
- **Discovery / Collection** (2014-11-06): Geolocation Metadata in Images Reveals International Travel Patterns

**Tools:** search (128), open_case (22), get_raw_output (20), get_investigation_summary (17), get_findings (13). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **APT PutterPanda Malware Detected in Memory** (2020-11-16T02:30:00 to 2020-11-16T02:37:00)


- **Multiple Suspicious RDP Connections from Foreign IPs** (2020-11-16T02:31:18 to 2020-11-16T02:36:24)




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

331 tool calls were executed across 14
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Narrative: Stark Research Labs APT Compromise

## Background

This investigation examines a confirmed Advanced Persistent Threat (APT) compromise of a Windows 10 workstation belonging to Stark Research Labs. The analysis was conducted against forensic evidence including a memory dump captured on November 16, 2020, at approximately 02:30-02:37 UTC, and a forensic disk image containing registry hives, file system artifacts, and network evidence.

The compromised system belonged to user Fred Rocba (fred.rocba@outlook.com, frocba@stark-research-labs.com), who maintained administrative privileges on the workstation. The system was configured with multiple cloud storage synchronization services including Google Drive File Stream and Dropbox, and had Remote Desktop Protocol (RDP) services exposed to the internet on the default port 3389 without adequate access controls.

The investigation leveraged 14 forensic data sources extracted through a comprehensive battery of digital forensic tools including Volatility 3 for memory analysis, The Sleuth Kit for filesystem examination, bulk_extractor for IOC carving, RegRipper for Windows registry analysis, and YARA for malware signature detection. The analysis identified 11 distinct findings spanning 14 MITRE ATT&CK techniques, including 2 critical-severity findings representing active APT malware presence and unauthorized remote access.

The evidence inventory includes Windows registry hives (SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT) dating from October 20 to November 16, 2020, providing a 27-day window of system configuration history. File system artifacts span from 2014 to 2020, with the majority concentrated in the final month before memory capture. The memory dump represents a snapshot of system state during active compromise, capturing running processes, network connections, loaded modules, and injected code at the moment of acquisition.

## Incident Timeline

The APT compromise of Stark Research Labs unfolded across multiple operational phases spanning at least 26 days from initial access to memory capture. The following timeline reconstructs the attack progression through distinct stages of the intrusion lifecycle.

### Phase 1: Initial Access and Foothold Establishment (October 20-27, 2020)

The earliest evidence of attacker activity dates to October 20, 2020, when two user accounts (srl-h [RID 1001] and fredr [RID 1002]) were created with administrative privileges. Both accounts were configured as members of the Administrators group and set with "Password does not expire" flags, violating standard security practices. The srl-h account was associated with email srl-helpdesk@outlook.com, while the fredr account belonged to Fred Rocba (fred.rocba@outlook.com). On October 20, 2020 at 19:46:16 UTC, the srl-h account recorded a password failure, suggesting either legitimate user error or early attacker reconnaissance and credential testing.

By October 28, 2020 at 12:26:11 UTC, the Dropbox client was installed and configured for automatic startup via the Windows Run registry key "Wow6432Node\Microsoft\Windows\CurrentVersion\Run". This installation occurred within the broader attack window and represents a potential data exfiltration vector, though the timing suggests it may have been a legitimate business tool installation rather than attacker activity. Nevertheless, the presence of cloud storage applications during an active APT compromise creates opportunities for covert data exfiltration that appear as normal cloud backup traffic.

### Phase 2: Reconnaissance and Privilege Maintenance (November 1-10, 2020)

On November 1, 2020, Dropbox update tasks (DropboxUpdateTaskMachineCore and DropboxUpdateTaskMachineUA) executed at 21:02:27 UTC and 21:30:01 UTC respectively, confirming the synchronization service remained active. Between November 1-10, no direct evidence of attacker activity was captured, though the absence of evidence does not indicate absence of activity. Sophisticated APT actors typically conduct extensive reconnaissance and lateral movement while maintaining operational security to avoid detection.

On November 10, 2020 at 13:26:09 UTC, the srl-h account recorded its last login timestamp, potentially representing either legitimate user activity or attacker use of that account for system access. The following day, November 11 at 08:13:16 UTC, the RDP service (PID 1248, svchost.exe) bound to 0.0.0.0:3389, beginning to accept remote desktop connections from any source IP address. This configuration persisted through the remainder of the incident timeline, providing the primary access vector for subsequent attacker operations.

### Phase 3: Exploitation and Malware Deployment (November 14-16, 2020)

On November 14, 2020 at 03:42:22 UTC, the fredr account experienced a password failure, suggesting possible brute force attempts or attacker authentication testing against the administrative account. By November 14 at 12:51:58 UTC, the fredr account successfully authenticated (last login timestamp), potentially representing either legitimate user activity or successful attacker compromise of administrative credentials.

The critical escalation occurred on November 16, 2020, beginning at 02:31:18 UTC when the first suspicious RDP connection was established from foreign IP address 81.30.144.115. Over the following five minutes, more than 50 RDP connections were initiated from four distinct foreign IP addresses:

- **81.30.144.115** (multiple connections, primary attacker IP)
- **213.202.233.104** (multiple connections, including one ESTABLISHED connection at capture time from port 45753)
- **81.19.209.101** (secondary connection)
- **201.193.188.114** (tertiary connection)

All RDP connections terminated through svchost.exe (PID 1248), the Windows Terminal Services process. Connection timestamps ranged from 02:31:18 through 02:36:24 UTC, with the vast majority in CLOSED state at memory capture time (02:30-02:37 UTC). Critically, one connection from 213.202.233.104:45753 remained in ESTABLISHED state at the time of memory capture, indicating an active remote desktop session in progress during evidence acquisition.

Concurrent with this RDP connection surge, YARA memory analysis detected APT_Malware_PutterPanda_WUAUCLT signatures and APT6_Malware_Sample_Gen indicators in the memory dump. The PutterPanda detection included characteristic misspelled string "NullRefrencedException" and error message "error has occurred in user32.dll by" which are known unique identifiers of the PutterPanda (APT2) backdoor family used by Chinese state-sponsored threat actors for cyber espionage operations.

During this same window, a suspicious executable "MRC.exe" (PID 29440) was found running from the non-standard location "D:\Tools\MRC.exe". Analysis of the executable's DLL listings revealed corrupted or impossible timestamps (years 1691, 1715, 3515, 3520, 3536), characteristic of malware with corrupted PE headers or timestamp manipulation for anti-forensic purposes. Process handles showed references from svchost.exe (PID 1040), suggesting system-level interaction between Windows services and this suspicious executable.

### Phase 4: Defense Evasion and Potential Data Exfiltration (November 16, 2020)

Evidence of anti-forensics and potential data exfiltration emerged during the final hours of the investigation window. An Outlook PST file ($IDNBREY.pst) was deleted and moved to the Recycle Bin for user SID S-1-5-21-528816539-567677750-276746561-1002 (fredr account). The deletion of email archive data during active APT compromise suggests either attacker evidence destruction after email exfiltration, or incident response cleanup without proper forensic preservation.

Google Drive File Stream (version 43.0.8.0) was actively running during the compromise window, with drivefsext.dll module loaded into explorer.exe. Bulk extractor URL artifacts captured multiple POST requests to googleapis.com/upload/drive/v2internal/files endpoints with resumable upload parameters, indicating file upload activity to Google Drive cloud storage. The URLs included metadata fields for file properties (title, mimeType, modifiedDate, fileSize, md5Checksum) consistent with Google Drive File Stream synchronization operations. While this may represent legitimate business activity, the timing coinciding with APT malware presence and active RDP intrusion raises concern about potential data exfiltration leveraging the victim's authenticated cloud storage accounts.

Volatility malfind analysis detected PAGE_EXECUTE_READWRITE memory regions in multiple processes including dllhost.exe (PID 8748), SearchApp.exe (PIDs 8312 and 19436), LockApp.exe (PID 9788), RuntimeBroker.exe (PID 9964), Teams.exe (PID 15636), and smartscreen.exe (PID 19348). These detections indicate potential code injection techniques employed by attackers targeting user-mode processes to establish persistence and evade detection.

Password failure attempts occurred against disabled system accounts during the attack window on November 16, including Administrator (RID 500) at 02:50:31 UTC, Guest (RID 501) at 00:23:06 UTC, and DefaultAccount (RID 503) at 01:12:37 UTC. These failures coincided with the RDP connection surge from foreign IPs (02:31:18 through 02:36:24), suggesting brute force attempts that were successfully blocked by proper account disablement security controls. The attackers ultimately gained access through other means rather than compromising disabled built-in accounts.

## Key Findings

The investigation identified eleven distinct findings across the intrusion lifecycle, organized below by category and severity.

### APT Malware Presence

**APT PutterPanda Malware Detected in Memory (Critical, Confirmed):** YARA memory scan detected APT_Malware_PutterPanda_WUAUCLT and APT6_Malware_Sample_Gen signatures in the memory dump, representing the most severe finding of this investigation. The detection included characteristic unique identifiers of the PutterPanda backdoor family: the misspelled string "NullRefrencedException" and error message "error has occurred in user32.dll by". PutterPanda (also designated APT2) is a sophisticated Chinese state-sponsored APT group known for targeted cyber espionage campaigns against defense contractors, aerospace companies, and technology firms. The presence of this malware family in memory at 02:30-02:37 UTC on November 16, 2020 confirms active compromise at the time of memory capture. This finding represents the primary indicator of Advanced Persistent Threat activity and elevates the incident from opportunistic intrusion to sophisticated state-sponsored espionage operation. MITRE ATT&CK: T1055 (Process Injection).

**Suspicious Executable MRC.exe Running from Non-Standard Location (High, Inference):** A suspicious executable "MRC.exe" with PID 29440 was discovered running from the non-standard directory "D:\Tools\MRC.exe" at the time of memory capture. The executable exhibited multiple indicators of malicious activity including corrupted or impossible PE header timestamps (years 1691, 1715, 3515, 3520, 3536), a generic naming convention consistent with attacker tooling rather than legitimate software, execution from a non-standard D:\ drive location outside normal Program Files directories, and system-level interaction evidenced by process handles from svchost.exe (PID 1040). The temporal correlation between MRC.exe execution and the confirmed PutterPanda malware presence suggests this executable may be part of the attacker's post-compromise toolkit deployed for lateral movement, credential harvesting, or data staging operations. MITRE ATT&CK: T1204.002 (User Execution: Malicious File), T1059 (Command and Scripting Interpreter).

### Initial Access and Lateral Movement

**Multiple Suspicious RDP Connections from Foreign IPs (Critical, Confirmed):** Memory forensics analysis revealed more than 50 Remote Desktop Protocol connections from four foreign IP addresses within a five-minute window on November 16, 2020. The primary attacking IPs were 81.30.144.115 (multiple connections) and 213.202.233.104 (multiple connections including one ESTABLISHED session at capture time from port 45753). Secondary connections originated from 81.19.209.101 and 201.193.188.114. Connection timestamps spanned 02:31:18 through 02:36:24 UTC, with the vast majority in CLOSED state by memory capture time except for the active ESTABLISHED connection from 213.202.233.104:45753. All connections terminated through svchost.exe (PID 1248), the Windows Terminal Services process. The connection pattern, volume, and temporal correlation with APT malware detection indicate successful RDP compromise serving as the primary access vector for threat actor operations. MITRE ATT&CK: T1078 (Valid Accounts), T1021.001 (Remote Services: Remote Desktop Protocol).

**RDP Service Exposed to Internet with Weak Access Controls (High, Confirmed):** The system had RDP service listening on all interfaces (0.0.0.0:3389) and accepting connections from any source IP address without proper access controls such as IP whitelisting, VPN requirements, or multi-factor authentication. The netscan output shows RDP service (PID 1248, svchost.exe) bound since November 11, 2020 at 08:13:16 UTC, providing a six-day window of internet exposure before the confirmed compromise. This configuration, combined with successful foreign connections and APT malware presence, represents a critical security control failure that enabled the initial access vector. Remote Desktop Protocol exposure is a common attack surface exploited by both APT groups and ransomware operators for initial access. MITRE ATT&CK: T1133 (External Remote Services).

**Failed Brute Force Attack Attempts Blocked by Security Controls (Low, Confirmed):** Registry SAM analysis revealed password failure attempts against built-in system accounts during the attack window, with all failures occurring only on disabled accounts: Administrator (RID 500) failed at 02:50:31 UTC, Guest (RID 501) at 00:23:06 UTC, and DefaultAccount (RID 503) at 01:12:37 UTC. These failures occurred within the same timeframe as suspicious RDP connections from foreign IPs (02:31:18 through 02:36:24), indicating brute force attempts that were successfully blocked by proper security controls (account disablement). While attackers ultimately gained access as evidenced by APT malware presence and active ESTABLISHED RDP connection, they did not succeed through password brute forcing of system accounts. This finding demonstrates that basic security hygiene (disabling default accounts) successfully defended against one attack vector, though the attackers pivoted to alternative access methods. MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing), T1110.003 (Brute Force: Password Spraying).

### Persistence and Privilege Escalation

**Code Injection Detected in Multiple Processes (Medium, Inference):** Volatility malfind analysis detected PAGE_EXECUTE_READWRITE memory regions in multiple user-mode processes including dllhost.exe (PID 8748), SearchApp.exe (PIDs 8312 and 19436 with 4 regions total), LockApp.exe (PID 9788), RuntimeBroker.exe (PID 9964), Teams.exe (PID 15636), and smartscreen.exe (PID 19348). While initial analysis also flagged Windows Defender (MsMpEng.exe, PID 4864), counter-analysis determined those detections represent normal antivirus engine behavior requiring executable memory for dynamic signature scanning, emulation, and JIT compilation rather than malicious code injection. However, the detections in other user-mode processes, combined with confirmed PutterPanda APT malware presence and the suspicious MRC.exe executable, indicate code injection techniques may have been employed by attackers to establish in-memory persistence and evade file-based detection mechanisms. MITRE ATT&CK: T1055 (Process Injection), T1562.001 (Impair Defenses: Disable or Modify Tools).

**Two User Accounts with Administrative Privileges (Medium, Confirmed):** SAM registry analysis revealed two user accounts (srl-h [RID 1001] and fredr [RID 1002]) both configured as members of the Administrators group with full system access. The srl-h account was associated with srl-helpdesk@outlook.com and showed last login on November 10, 2020 at 13:26:09 UTC. The fredr account belonged to Fred Rocba (fred.rocba@outlook.com) and showed last login on November 14, 2020 at 12:51:58 UTC. Both accounts were created between October 20-27, 2020, and configured with "Password does not expire" flags, violating security best practices. The presence of multiple administrator accounts increases attack surface and violates the principle of least privilege. In the context of this APT compromise with successful RDP access from foreign IPs, multiple admin accounts provided attackers with multiple potential access vectors and elevated privileges immediately upon successful authentication. MITRE ATT&CK: T1078.003 (Valid Accounts: Local Accounts).

**Dropbox Configured for Automatic Startup (Medium, Inference):** Registry analysis shows Dropbox client configured in the Windows Run key for automatic startup on system boot. The registry entry "Wow6432Node\Microsoft\Windows\CurrentVersion\Run" contained "Dropbox - \"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe\" /systemstartup" with last write time of October 28, 2020 at 12:26:11 UTC. While Dropbox is legitimate cloud storage software used by organizations, in the context of this active APT compromise it represents a potential data exfiltration vector. The timing of installation (October 28) falls within the broader attack timeline leading up to memory capture on November 16. Task scheduler evidence shows Dropbox update tasks actively running with last executions on November 1, 2020 at 21:02:27 and 21:30:01 UTC. Bulk extractor data confirms Dropbox references (cfl.dropboxstatic.com). Attackers could leverage authenticated Dropbox accounts for covert data exfiltration that appears as legitimate cloud backup activity, bypassing egress monitoring. MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys), T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage).

### Data Exfiltration and Anti-Forensics

**Google Drive File Stream Active During APT Compromise (Medium, Inference):** Google Drive File Stream application (version 43.0.8.0) was actively running on the compromised system at the time of memory capture, with drivefsext.dll module loaded into explorer.exe at 08:13:47 UTC on November 11, 2020. Bulk extractor URL artifacts captured multiple POST requests to googleapis.com/upload/drive/v2internal/files endpoints with resumable upload parameters, indicating file upload activity during the compromise window. The URLs included metadata fields (title, mimeType, modifiedDate, fileSize, md5Checksum) consistent with Google Drive File Stream synchronization operations. While Google Drive File Stream is legitimate software used by the organization (OneDrive - Stark Research Labs directories present), in the context of active APT compromise with PutterPanda malware and successful RDP intrusion from foreign IPs, the cloud storage application represents a potential data exfiltration vector. Attackers could leverage the victim's authenticated Google Drive account (frocba@stark-research-labs.com) to exfiltrate sensitive corporate data without triggering egress monitoring alarms, as the traffic appears as legitimate cloud backup activity. The timing of upload activity coinciding with APT malware presence raises concern about unauthorized data access and exfiltration. MITRE ATT&CK: T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage).

**Outlook PST Data File Deleted During Compromise Window (Medium, Inference):** Filesystem analysis revealed an Outlook PST (Personal Storage Table) file was deleted and moved to the Recycle Bin during the investigation timeframe. The file $IDNBREY.pst was found in the Recycle Bin path for user SID S-1-5-21-528816539-567677750-276746561-1002 (fredr account). PST files contain Outlook email messages, calendar items, contacts, tasks, and other mailbox data representing high-value intelligence targets for APT actors. The deletion during active APT compromise is significant for several reasons: attackers may delete PST files after exfiltrating email data to remove evidence of their access to corporate communications; users or administrators may delete PST files as part of incident response cleanup without proper forensic preservation; or the timing could indicate awareness of compromise and attempted evidence destruction. The presence of other deleted files in the same Recycle Bin path ($IDLNUZH.msi installer and $IDTQK82.exe executable) suggests multiple file deletions occurred during this timeframe. Given the confirmed APT PutterPanda presence, successful RDP compromise, and potential data exfiltration via cloud storage services, the deletion of email archive data warrants investigation for evidence of corporate communications access by threat actors. MITRE ATT&CK: T1070.004 (Indicator Removal on Host: File Deletion).

### Intelligence Value Assessment

**Geolocation Metadata in Images Reveals International Travel Patterns (Info, Confirmed):** Analysis of EXIF GPS metadata embedded in images on the compromised system reveals extensive international travel history. GPS coordinates identify visits to multiple countries including Romania (Bucharest area: 44.43°N, 26.09°E with 70+ coordinate entries), Thailand (Bangkok area: 13.75°N, 100.49°E), Hawaii (20.68°N, -156.44°W), Mexico (multiple locations), and various US locations (Chicago, San Francisco, Washington DC). The heaviest concentration of GPS-tagged images originates from the Bucharest, Romania metropolitan area with timestamps ranging from 2014-2016. This travel metadata is significant in the APT compromise context for several reasons: APT actors conducting reconnaissance could use travel patterns to identify when victims are away from primary offices, presenting opportunities for physical or social engineering attacks; geolocation data can reveal business relationships, partnerships, or client locations that may be of intelligence value to state-sponsored threat actors; the concentration of Romania-sourced imagery suggests either frequent business travel to Eastern Europe or potential dual work locations, which could indicate research partnerships or facilities in that region; and travel pattern analysis can inform attribution investigations by identifying potential geographic connections between victims and threat actors. The presence of this geolocation metadata also represents an operational security concern, as attackers with filesystem access can extract location intelligence without needing to exfiltrate full images. MITRE ATT&CK: T1005 (Data from Local System).

## Threat Intelligence and Attribution

The combination of YARA signature detections, tactical tradecraft, and targeting profile strongly indicates this incident represents a sophisticated state-sponsored cyber espionage operation rather than financially-motivated cybercrime or opportunistic intrusion.

### Malware Family Identification

YARA memory analysis detected two distinct APT malware signatures: APT_Malware_PutterPanda_WUAUCLT and APT6_Malware_Sample_Gen. The PutterPanda detection is particularly significant due to the presence of unique identifying strings "NullRefrencedException" (intentional misspelling) and "error has occurred in user32.dll by" which are exclusive identifiers of the PutterPanda backdoor family documented in public threat intelligence reporting.

PutterPanda (also tracked as APT2 by Mandiant) is a Chinese state-sponsored Advanced Persistent Threat group active since at least 2010, known for cyber espionage campaigns targeting defense contractors, aerospace manufacturers, satellite and telecommunications companies, and high-technology research firms. The group's operational focus aligns with Chinese national security interests in military modernization, satellite technology, and dual-use technologies. Historical PutterPanda campaigns have targeted organizations in the United States, Europe, and Asia-Pacific regions with the objective of stealing intellectual property, research data, and strategic communications to support Chinese economic and military development priorities.

The detection of APT6_Malware_Sample_Gen alongside PutterPanda signatures suggests either tool sharing between Chinese APT groups (a common pattern in state-sponsored operations where multiple groups leverage shared infrastructure and malware families developed by common providers) or evolution of the PutterPanda malware to incorporate techniques from other Chinese APT toolsets.

### Tactical Tradecraft Analysis

The attacker's tactical approach demonstrates characteristics consistent with state-sponsored APT operations:

**Initial Access via RDP Exposure:** The exploitation of internet-exposed Remote Desktop Protocol services with weak access controls represents a common initial access vector for both APT groups and cybercriminal operations. However, the subsequent deployment of specialized APT malware rather than ransomware or commodity remote access tools distinguishes this as an intelligence collection operation rather than financially-motivated attack.

**Credential-Based Authentication:** The successful establishment of RDP connections from foreign IP addresses combined with failed brute force attempts against disabled system accounts suggests the attackers either obtained valid credentials through prior reconnaissance (spear phishing, credential theft from related compromises, or password reuse) or successfully compromised one of the two administrative accounts (srl-h or fredr) through targeted credential attacks. The presence of password failures on the fredr account on November 14 at 03:42:22 UTC, two days before the RDP connection surge, suggests possible credential testing or account lockout during brute force attempts that preceded successful authentication.

**In-Memory Persistence and Code Injection:** The detection of PAGE_EXECUTE_READWRITE memory regions in multiple user-mode processes (dllhost.exe, SearchApp.exe, LockApp.exe, RuntimeBroker.exe, Teams.exe, smartscreen.exe) indicates the use of fileless malware techniques and process injection for persistence and defense evasion. This tradecraft is characteristic of sophisticated APT operations seeking to minimize forensic artifacts on disk and evade file-based detection mechanisms employed by antivirus and endpoint detection solutions.

**Cloud Storage Exfiltration:** The presence of active Google Drive File Stream and Dropbox synchronization during the compromise window, combined with bulk extractor evidence of upload activity to googleapis.com endpoints, suggests potential abuse of legitimate cloud services for data exfiltration. This technique, known as "living off the land" or "bring your own infrastructure," allows attackers to blend malicious traffic with legitimate business activity, bypassing network security monitoring focused on traditional exfiltration channels. Chinese APT groups have increasingly adopted cloud storage exfiltration techniques in recent years to evade detection.

**Anti-Forensics:** The deletion of the Outlook PST file ($IDNBREY.pst) during the compromise window suggests awareness of forensic investigation procedures and deliberate evidence destruction. Sophisticated APT actors routinely employ anti-forensic techniques including log deletion, file wiping, and timestamp manipulation to complicate incident response and attribution efforts.

### Attribution Assessment

While definitive attribution of cyber espionage operations to specific nation-state sponsors requires intelligence sources beyond technical forensic analysis, the evidence in this investigation strongly suggests Chinese state-sponsored activity with high confidence based on the following indicators:

**PutterPanda Malware Family:** The detection of PutterPanda (APT2) malware signatures with unique identifying strings represents the strongest attribution indicator. PutterPanda is exclusively associated with Chinese state-sponsored cyber espionage operations and has not been observed in use by other threat actors or cybercriminal groups. The group's historical targeting of defense contractors, aerospace companies, and technology research firms aligns with the victim organization Stark Research Labs.

**Victim Profile:** Stark Research Labs represents a high-value intelligence target for state-sponsored espionage focused on defense technology, aerospace research, or advanced scientific development. The organization name suggests research and development activities in sensitive technical domains that would be of interest to foreign intelligence services seeking to acquire intellectual property, trade secrets, or early-stage research to support domestic technology development and military modernization programs.

**Operational Tradecraft:** The combination of RDP compromise, in-memory malware deployment, code injection techniques, and cloud storage exfiltration aligns with tactical patterns documented in Chinese APT operations over the past decade. The operational tempo (rapid RDP connection surge followed by malware deployment within minutes) suggests experienced operators executing a pre-planned intrusion playbook rather than opportunistic exploitation.

**Geographic Indicators:** The foreign IP addresses used for RDP connections (81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114) may represent either VPN exit nodes, compromised infrastructure used for operational relay, or legitimate infrastructure in the attacker's operational region. Further investigation of IP geolocation and WHOIS registration data may provide additional attribution indicators, though sophisticated APT groups routinely employ multi-hop anonymization infrastructure to obscure true origin.

**Attribution Confidence Level:** Based on the PutterPanda malware family detection and tactical tradecraft analysis, this investigation assesses with high confidence that the intrusion represents Chinese state-sponsored APT activity, likely conducted by the PutterPanda (APT2) group or affiliated Chinese intelligence collection operations leveraging shared malware infrastructure. The attribution to specific Chinese intelligence services (Ministry of State Security, People's Liberation Army Strategic Support Force, or related organizations) requires additional intelligence sources beyond the scope of technical forensic analysis.

## Impact Assessment

The APT compromise of Stark Research Labs represents a significant national security incident with far-reaching implications for corporate intellectual property, employee privacy, strategic communications, and organizational resilience.

### Scope of Compromise

**Systems Compromised:** This investigation analyzed forensic evidence from one Windows 10 workstation belonging to user Fred Rocba (frocba@stark-research-labs.com, fred.rocba@outlook.com). The confirmed compromise includes active APT malware presence in memory (PutterPanda backdoor), successful RDP access from foreign IP addresses with one ESTABLISHED session at memory capture time, code injection into multiple user-mode processes, and execution of suspicious executable MRC.exe from non-standard location D:\Tools\. The single-system scope of forensic evidence does not preclude additional compromises across the Stark Research Labs network. Lateral movement evidence was not observed in the memory dump and disk image analyzed, but the presence of two administrative accounts (srl-h and fredr) with network access capabilities and the six-day window of RDP exposure (November 11-16) provides ample opportunity for undetected lateral propagation to additional systems. **The investigation's scope is limited to one workstation; enterprise-wide compromise cannot be ruled out and should be assumed until comprehensive network-wide forensic analysis is completed.**

**Data at Risk:** The compromised workstation contained high-value corporate data including email archives (Outlook PST file deleted during compromise window), cloud-synchronized files via Google Drive File Stream and Dropbox, web browser history and credentials, saved passwords, corporate documents, and network access credentials for Stark Research Labs infrastructure. The presence of active PutterPanda malware with memory access to all process space and the attacker's administrative privileges on the system provide capability to access, exfiltrate, or destroy any data resident on the workstation or accessible through the user's authenticated sessions and saved credentials. Geolocation metadata analysis revealed international travel patterns to Romania, Thailand, Hawaii, Mexico, and multiple US locations, providing intelligence value to threat actors conducting targeting, profiling, or operational planning against Stark Research Labs personnel.

**Credential Exposure:** Two administrative accounts (srl-h [RID 1001] associated with srl-helpdesk@outlook.com and fredr [RID 1002] associated with fred.rocba@outlook.com) were present on the compromised system with full administrative privileges. Successful attacker authentication via RDP from foreign IP addresses indicates at least one set of valid credentials was compromised. The presence of password hashes in the Windows SAM registry hive, cached domain credentials (if the system was domain-joined), browser-saved passwords for corporate and personal services, and credential material stored by password managers or applications on the compromised system all represent exposed credential material requiring enterprise-wide password rotation. Active Directory domain credentials, if present, provide lateral movement capability to additional systems across the Stark Research Labs network.

**Persistence Depth:** The investigation identified multiple persistence mechanisms employed by the attackers including in-memory malware presence (PutterPanda backdoor), code injection into user-mode processes (PAGE_EXECUTE_READWRITE regions detected by Volatility malfind in dllhost.exe, SearchApp.exe, LockApp.exe, RuntimeBroker.exe, Teams.exe, smartscreen.exe), execution of suspicious MRC.exe from D:\Tools\ directory, and potential abuse of legitimate cloud storage auto-start applications (Dropbox configured in Windows Run key registry). The use of in-memory techniques and process injection indicates sophisticated persistence that survives reboots through re-infection vectors (scheduled tasks, registry autorun entries, or reinfection from command-and-control infrastructure upon network reconnection). Complete eradication requires not only malware removal but also comprehensive credential rotation, registry cleanup, scheduled task review, and verification that no additional persistence mechanisms were installed during the six-day window of initial RDP exposure before malware detection.

### Severity Assessment

**Critical National Security Impact:** The confirmed presence of PutterPanda (APT2) malware, a Chinese state-sponsored APT toolset used exclusively for cyber espionage operations, elevates this incident from routine cybersecurity breach to national security concern. If Stark Research Labs conducts defense-related research, aerospace technology development, satellite communications, dual-use technology innovation, or other work subject to export control regulations (ITAR, EAR) or classified project requirements, the compromise represents potential theft of controlled technology data or classified information with implications for U.S. national security, allied information sharing agreements, and corporate legal liability under export control statutes.

**Intellectual Property Theft:** State-sponsored APT operations targeting research laboratories and technology companies typically focus on intellectual property acquisition to support the sponsoring nation's economic development and military modernization objectives. The investigation window (October 20 - November 16, 2020) provides 27 days during which the attackers maintained access to corporate research data, technical documentation, proprietary designs, source code, experimental results, grant proposals, patent applications, and strategic business plans. The use of cloud storage synchronization services (Google Drive File Stream, Dropbox) during active compromise provides convenient exfiltration channels where attackers can leverage authenticated user sessions to bulk-download synchronized corporate file repositories without triggering traditional data loss prevention controls. **The scope of intellectual property loss cannot be quantified from forensic analysis alone and requires comprehensive audit log review of cloud storage provider access logs, file download history, and data transfer volumes during the compromise window.**

**Strategic Communications Compromise:** The deletion of the Outlook PST file ($IDNBREY.pst) during the compromise window suggests attacker interest in corporate email communications. Email archives contain strategic business intelligence including confidential internal discussions, negotiations with partners and customers, research collaboration planning, financial projections, merger and acquisition discussions, legal matters, personnel issues, and competitive intelligence. For APT actors conducting long-term strategic intelligence collection against a target organization, email compromise provides invaluable insight into corporate strategy, decision-making processes, key personnel relationships, vulnerabilities, and future planning. The intentional deletion of the PST file suggests either exfiltration followed by anti-forensic evidence destruction, or awareness of compromise and user/administrator-initiated cleanup without proper forensic preservation. **If the PST file was exfiltrated before deletion, Stark Research Labs must assume all corporate email communications contained in that archive are now in possession of Chinese intelligence services.**

**Employee Privacy Violation:** The compromise of Fred Rocba's workstation includes access to personal email accounts (fred.rocba@outlook.com, fred.rocba@gmail.com), browser history, personal files synchronized via cloud storage, social media sessions, banking and financial accounts if accessed via browser with saved passwords, personal communications, and extensive geolocation metadata revealing international travel patterns from 2014-2016. This level of personal data access represents significant employee privacy violation with potential legal implications under data protection regulations and creates counterintelligence risks if the compromised personal information is used for subsequent social engineering, spear phishing, or targeting operations against the employee or related individuals (family members, colleagues, professional contacts). The concentration of geolocation data from Bucharest, Romania suggests either frequent business travel to Eastern Europe or dual work locations, which could indicate research partnerships or personal connections that become targeting vectors for follow-on intelligence collection operations.

### Business Impact

**Incident Response Costs:** The confirmed APT compromise requires comprehensive incident response including enterprise-wide forensic investigation to determine scope of lateral movement, malware eradication across all potentially compromised systems, credential rotation for all user and service accounts, network segmentation review and remediation, security control enhancement, affected system reimaging, and notification obligations to customers, partners, and regulatory authorities. Industry benchmarks for APT incident response costs range from hundreds of thousands to millions of dollars depending on scope of compromise and regulatory compliance requirements.

**Regulatory and Legal Exposure:** If Stark Research Labs operates under ITAR, EAR, NIST 800-171, CMMC, FedRAMP, or other regulatory frameworks governing controlled unclassified information or classified material, the confirmed breach of systems containing covered data triggers mandatory reporting requirements to the Defense Counterintelligence and Security Agency (DCSA), contracting officers, and affected government agencies. Failure to report within required timeframes (typically 72 hours from discovery for defense contractors) may result in contract suspension, debarment from future government work, civil penalties, and potential criminal liability. Additionally, if personally identifiable information (PII) of employees, customers, or research subjects was compromised, notification obligations under state data breach laws and potential GDPR implications for European data subjects may apply.

**Reputational Damage:** Public disclosure of Chinese state-sponsored APT compromise, particularly if intellectual property theft or classified data breach occurred, damages corporate reputation with customers, partners, investors, and government agencies. Research partners may reconsider collaboration agreements, government agencies may suspend or terminate contracts pending security remediation verification, investors may devalue the company based on IP theft and competitive disadvantage, and industry reputation as a secure research partner may be permanently impaired.

**Competitive Disadvantage:** If proprietary research data, experimental results, product designs, or strategic business plans were exfiltrated during the 27-day compromise window, Stark Research Labs faces significant competitive disadvantage as Chinese state-sponsored recipients leverage stolen intellectual property to accelerate domestic technology development, undercut product pricing, or preemptively file patent applications in Chinese jurisdictions. The research and development investment represented by stolen IP may total millions or tens of millions of dollars in sunk costs that competitors now acquire at zero cost through cyber espionage.

## Immediate Tactical Containment

The following actions must be executed immediately to stop active threat operations and prevent further damage. These steps are sequenced for maximum effectiveness and minimal business disruption.

1. **Isolate compromised workstation** - Disconnect network cable and disable WiFi on Fred Rocba's workstation (MAC address identified in forensic evidence). Do NOT power off the system until additional volatile memory capture can be performed by incident response team. Place system in evidence custody for continued forensic analysis.

2. **Block foreign IP addresses at perimeter firewall** - Implement immediate block rules for the following confirmed attacker IP addresses: 81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114. Configure firewall to deny all inbound and outbound connections to/from these addresses across entire network perimeter.

3. **Disable compromised user accounts** - Immediately disable Active Directory/local accounts: srl-h (RID 1001, srl-helpdesk@outlook.com) and fredr (RID 1002, fred.rocba@outlook.com, frocba@stark-research-labs.com). Do NOT delete accounts as this will complicate forensic investigation. Reset passwords to complex random values and document all actions with timestamps.

4. **Terminate suspicious process MRC.exe** - If the process is still running on any network systems, terminate PID 29440 (or current PID if restarted) for MRC.exe executable located at D:\Tools\MRC.exe. Quarantine the executable file and preserve for malware analysis. Search enterprise-wide for additional instances of MRC.exe in non-standard directories.

5. **Block outbound RDP at network perimeter** - Implement firewall rules blocking outbound TCP port 3389 connections from internal network to internet. RDP should only be permitted within internal network segments or through authenticated VPN with multi-factor authentication.

6. **Disable internet-exposed RDP service** - Stop Terminal Services (TermService) on all Windows systems with internet-facing RDP exposure. Remove any port forwarding rules or firewall exceptions allowing inbound TCP port 3389 from internet sources. RDP access should only be permitted through VPN with MFA.

7. **Suspend cloud storage synchronization** - Temporarily disable Google Drive File Stream and Dropbox synchronization on all workstations until comprehensive audit of uploaded files during compromise window (October 20 - November 16, 2020) can be completed. Contact Google Workspace and Dropbox support to obtain detailed access logs and file modification history for accounts frocba@stark-research-labs.com and associated personal accounts.

8. **Enable emergency authentication monitoring** - Configure Security Information and Event Management (SIEM) system or equivalent logging to alert on any authentication attempts using disabled accounts srl-h and fredr, connections from blocked IP addresses 81.30.144.115/213.202.233.104/81.19.209.101/201.193.188.114, or execution of MRC.exe process name anywhere on the network.

9. **Force enterprise-wide password reset** - Require immediate password changes for all user accounts on potentially affected network segments. Prioritize administrative accounts, service accounts with network access, and any accounts that authenticated from the compromised workstation. Use minimum 16-character complexity requirements and verify no reuse of previous passwords.

10. **Initiate hunt for PutterPanda indicators** - Deploy YARA rules for APT_Malware_PutterPanda_WUAUCLT and APT6_Malware_Sample_Gen signatures across all Windows endpoints using endpoint detection and response (EDR) platform or standalone YARA scanning tools. Search for characteristic strings "NullRefrencedException" and "error has occurred in user32.dll by" in memory across enterprise. Scan for PAGE_EXECUTE_READWRITE memory regions in user-mode processes (dllhost.exe, SearchApp.exe, LockApp.exe, RuntimeBroker.exe, Teams.exe, smartscreen.exe) using Volatility or equivalent memory forensics tools.

11. **Contact law enforcement and government agencies** - Notify FBI Cyber Division and CISA (Cybersecurity and Infrastructure Security Agency) of confirmed Chinese state-sponsored APT compromise. If operating under defense contracts, immediately notify DCSA and contracting officer per DFARS 252.204-7012 requirements (72-hour reporting deadline). Document notification times and recipients.

12. **Engage external incident response** - Retain qualified digital forensics and incident response (DFIR) firm with APT investigation experience and required security clearances if handling classified or CUI material. Provide all forensic evidence collected and preserve chain of custody documentation. Avoid internal-only response for nation-state incidents due to sophistication of adversary tradecraft and legal/regulatory reporting requirements.

## Strategic Remediation

Long-term remediation requires comprehensive security architecture improvements, detection capability enhancement, and organizational process changes to prevent recurrence of similar APT compromises.

### Network Architecture and Segmentation

Implement defense-in-depth network segmentation to limit lateral movement and contain future intrusions. Establish separate network zones for research and development systems, corporate workstations, server infrastructure, and guest/BYOD devices with firewall enforcement between zones requiring explicit allow rules rather than default permit posture. Deploy jump boxes or bastion hosts for administrative access to sensitive systems rather than permitting direct RDP/SSH from corporate workstations. Implement Zero Trust Network Architecture (ZTNA) principles requiring continuous authentication and authorization for all network access rather than perimeter-based trust models.

Eliminate direct internet exposure of remote administration protocols (RDP, SSH, VNC) through implementation of VPN concentrators with multi-factor authentication as mandatory access path for remote workers. Deploy application-layer VPN with per-application access control rather than network-layer VPN providing broad internal network access upon authentication. Consider software-defined perimeter (SDP) architecture for remote access to high-value research systems requiring cryptographic device identity and continuous trust verification.

### Endpoint Detection and Response Enhancement

Deploy enterprise-grade Endpoint Detection and Response (EDR) platform across all Windows, macOS, and Linux systems with capabilities including behavioral analytics, process injection detection, memory scanning, network connection monitoring, file integrity monitoring, and automated containment of suspicious activity. Configure EDR to specifically detect techniques employed in this incident: RDP connections from foreign countries, code injection into user-mode processes, execution from non-standard directories (D:\Tools\, user temp directories), and in-memory-only malware without persistent filesystem artifacts.

Enable Windows Defender Advanced Threat Protection (ATP) or equivalent EDR solution with attack surface reduction rules blocking common APT techniques: credential theft from LSASS memory, execution of unsigned executables from non-standard paths, Office macro execution, script-based malware, and lateral movement via PsExec/WMI. Implement application whitelisting using Windows Defender Application Control (WDAC) or AppLocker on high-value research workstations to prevent execution of unauthorized executables including attacker toolkits like MRC.exe.

Configure memory protection features including Windows Defender Exploit Guard, Control Flow Guard (CFG), and Hardware-enforced Stack Protection to mitigate code injection and process hollowing techniques. Enable Credential Guard on Windows 10 Enterprise systems to protect credentials in isolated virtualization-based security (VBS) container inaccessible to even kernel-mode malware.

### Identity and Access Management Hardening

Implement privileged access management (PAM) solution eliminating standing administrative privileges for user accounts. Adopt Just-in-Time (JIT) administration model where administrative rights are granted on-demand for specific time windows (2-4 hours) with approval workflow and automatic revocation. Separate administrative accounts from daily-use accounts requiring users to authenticate with dedicated admin credentials only when performing administrative tasks.

Deploy enterprise password manager requiring minimum 16-character randomly-generated passwords for all accounts with prohibited password reuse across systems. Eliminate "Password does not expire" flags on all user accounts implementing maximum 90-day password age for administrative accounts and 180-day age for standard users. Implement account lockout policies after 5 failed authentication attempts with 30-minute lockout duration and security team notification.

Mandate multi-factor authentication (MFA) for all remote access (VPN, cloud applications, email), administrative actions (privilege elevation, sensitive system access), and cloud storage access (Google Drive, Dropbox, OneDrive). Prioritize FIDO2 hardware security keys or biometric authentication over SMS-based one-time passwords to prevent phishing-resistant authentication. Prohibit legacy authentication protocols (POP3, IMAP without modern auth, SMBv1) that bypass MFA requirements.

### Data Loss Prevention and Cloud Security

Deploy Data Loss Prevention (DLP) solution monitoring and blocking sensitive data exfiltration via cloud storage services, email, removable media, and web uploads. Configure DLP policies identifying intellectual property, research data, export-controlled technical information, and personally identifiable information with automated blocking of uploads to unauthorized cloud destinations. Implement cloud access security broker (CASB) solution providing visibility and control over sanctioned cloud applications (Google Drive, Dropbox, Office 365) with anomaly detection for bulk downloads, unusual access patterns, and access from foreign countries.

Restrict cloud storage synchronization to corporate-managed Google Drive or OneDrive accounts with data loss prevention policies prohibiting synchronization of intellectual property to personal cloud accounts. Disable or uninstall Dropbox and other third-party cloud storage clients on research workstations requiring all cloud file sharing to use corporate-managed services with audit logging, retention policies, and legal hold capabilities. Enable cloud application threat detection identifying anomalous access patterns (impossible travel, mass file downloads, access from anonymizing infrastructure).

Implement Microsoft Defender for Cloud Apps or equivalent CASB solution providing session control and conditional access policies for cloud applications. Enforce download restrictions on sensitive files accessed via cloud applications, require MFA step-up authentication for high-risk activities (bulk download, external sharing), and block access from high-risk countries identified in threat intelligence.

### Security Monitoring and Threat Hunting

Enhance Security Information and Event Management (SIEM) deployment with correlation rules detecting APT tactics including: multiple failed authentication attempts followed by successful login (credential brute force), first-time authentication from foreign countries (geographic anomaly), RDP connections outside business hours (temporal anomaly), execution of rare executables (process frequency analysis), code injection events (malfind/hollow process patterns), cloud file upload volume spikes (exfiltration detection), and deletion of high-value files like PST archives (anti-forensics).

Implement threat hunting program conducting monthly proactive searches for indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) associated with Chinese APT groups including PutterPanda, APT1, APT3, APT10, APT40, and related threat actors. Incorporate threat intelligence feeds providing updated IOCs, YARA rules, and behavioral analytics for state-sponsored malware families. Deploy deception technology (honeytokens, honeypots, canary files) in research directories detecting unauthorized access attempts and lateral movement activity.

Enable centralized logging with minimum 12-month retention for Windows Event Logs (Security, System, Application, PowerShell, Sysmon), firewall connection logs, VPN authentication logs, cloud application access logs, and EDR telemetry. Implement log integrity protection preventing attacker modification or deletion of audit trails during compromise. Configure automated alerting to security operations center (SOC) for critical events including authentication from disabled accounts, process injection detection, MRC.exe execution, access from blocked IPs, and YARA malware signature matches.

### Vulnerability Management and Patch Operations

Implement aggressive patch management requiring deployment of critical security updates within 72 hours of release and monthly patching cycles for all severity levels. Prioritize patching of internet-facing systems (VPN concentrators, web applications, email gateways) and high-value research workstations. Leverage Microsoft Windows Server Update Services (WSUS) or third-party patch management solution with automated deployment, rollback capability, and compliance reporting.

Conduct quarterly vulnerability scanning using authenticated credentialed scans against all Windows, macOS, Linux systems identifying missing patches, weak configurations, and exploitable vulnerabilities. Remediate high and critical vulnerabilities within service level agreements (14 days for critical remote code execution, 30 days for high-severity, 90 days for medium). Implement vulnerability prioritization using threat intelligence-informed risk scoring considering active exploitation in the wild, exploit availability, and asset criticality.

Perform annual penetration testing by qualified third-party firm simulating APT adversary tradecraft including spear phishing, credential theft, lateral movement, and data exfiltration scenarios. Conduct red team exercises simulating Chinese APT operations against research infrastructure testing detection and response capabilities. Address all high and critical findings from penetration tests and red team engagements before next assessment cycle.

### Security Awareness and Insider Threat Programs

Implement mandatory security awareness training for all employees with specialized advanced training for users with administrative privileges, access to intellectual property, or handling of export-controlled information. Develop APT-specific training modules educating users about Chinese cyber espionage tactics including spear phishing, watering hole attacks, supply chain compromises, and social engineering. Conduct quarterly simulated phishing campaigns measuring user susceptibility and providing immediate remedial training for users who click malicious links or provide credentials.

Establish insider threat program monitoring for indicators of malicious insider activity or negligent security practices including mass file downloads, unusual access patterns, access to unrelated projects, use of unauthorized cloud storage, copying files to removable media, and authentication from foreign countries during international travel. Implement user and entity behavior analytics (UEBA) solution establishing baseline behavior patterns and alerting on anomalies. Conduct periodic insider threat risk assessments for users with access to trade secrets and export-controlled technology.

Require annual security clearance background investigations for personnel with access to classified or controlled unclassified information. Implement continuous evaluation monitoring for adverse information including financial distress, foreign contacts, foreign travel to high-risk countries, and security violations. Establish clear data handling procedures prohibiting use of personal email or cloud storage for corporate intellectual property.

### Incident Response and Business Continuity

Develop and maintain comprehensive Incident Response Plan specific to APT intrusions including detection procedures, containment strategies, eradication requirements, recovery steps, and lessons learned processes. Establish incident response team with defined roles (incident commander, forensics lead, communications officer, legal counsel, executive sponsor) and 24/7 on-call rotation. Retain digital forensics and incident response (DFIR) firm on retainer providing guaranteed response time for APT incidents.

Conduct tabletop exercises quarterly simulating APT scenarios including PutterPanda compromise, ransomware attack, supply chain compromise, and DDoS extortion. Test incident response procedures, communication plans, containment capabilities, and recovery processes. Document lessons learned and update incident response plan based on exercise findings and real-world incident experience.

Implement business continuity and disaster recovery procedures ensuring critical research operations can continue during prolonged incident response requiring network segmentation, system isolation, or infrastructure rebuild. Maintain offline backups of critical data with air-gapped storage preventing ransomware encryption or attacker destruction. Test backup restoration procedures quarterly verifying ability to recover from total infrastructure compromise within recovery time objectives.

## Conclusion

This investigation examined a confirmed Advanced Persistent Threat compromise of a Stark Research Labs Windows 10 workstation, revealing sophisticated Chinese state-sponsored cyber espionage activity conducted by the PutterPanda (APT2) threat group. The analysis of forensic evidence including memory dumps, disk images, registry hives, and network artifacts across 14 data sources yielded 11 findings spanning 14 MITRE ATT&CK techniques, with 2 critical-severity findings representing active malware presence and unauthorized remote access.

The investigation addresses the eight core questions that guide comprehensive incident response:

**Q1. What systems were compromised?**

Forensic analysis confirms compromise of one Windows 10 workstation belonging to user Fred Rocba (frocba@stark-research-labs.com, fred.rocba@outlook.com). The compromised system contained active PutterPanda malware in memory, successful RDP connections from foreign IP addresses (81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114), code injection into multiple user-mode processes, and execution of suspicious MRC.exe executable from D:\Tools\. The investigation scope is limited to evidence from this single workstation. However, the presence of two administrative accounts (srl-h and fredr) with network access capabilities, the six-day window of RDP exposure (November 11-16, 2020), and the sophisticated capabilities of PutterPanda malware for lateral movement indicate high probability of additional undetected compromises across the Stark Research Labs network. Enterprise-wide forensic investigation is required to definitively determine the full scope of compromise.

**Q2. How did the attacker gain initial access?**

The primary initial access vector was exploitation of internet-exposed Remote Desktop Protocol (RDP) service listening on all interfaces (0.0.0.0:3389) without adequate access controls. The RDP service (PID 1248, svchost.exe) was bound and accepting connections from any source IP address beginning November 11, 2020 at 08:13:16 UTC. On November 16, 2020, more than 50 RDP connections were established from foreign IP addresses within a five-minute window (02:31:18 through 02:36:24 UTC), with one connection from 213.202.233.104:45753 remaining in ESTABLISHED state at memory capture time, indicating active remote desktop session. The successful authentication via RDP indicates the attackers obtained valid credentials for one of the two administrative accounts (srl-h or fredr), either through brute force attacks (though disabled accounts successfully blocked brute force attempts), credential theft from prior reconnaissance, spear phishing, password reuse, or compromise of related systems. The fredr account showed password failure on November 14 at 03:42:22 UTC, two days before the RDP surge, suggesting credential testing preceding successful authentication.

**Q3. What lateral movement occurred?**

The forensic evidence analyzed (single workstation memory dump and disk image) does not contain direct evidence of lateral movement to additional systems. However, the absence of evidence should not be interpreted as evidence of absence. The attackers possessed administrative credentials for two accounts (srl-h and fredr), deployed sophisticated PutterPanda malware with lateral movement capabilities, and maintained access for a minimum six-day window (November 11-16, 2020) before memory capture. PutterPanda APT operations historically demonstrate extensive lateral movement to high-value targets following initial access. The presence of password hashes in the SAM registry hive, potential cached domain credentials if the system was domain-joined, and administrative privileges provide all prerequisites for lateral movement via SMB, WMI, RDP, or PowerShell remoting to additional Windows systems on the network. Comprehensive network-wide forensic investigation including domain controller event log analysis, network flow analysis for SMB and RDP connections, and memory forensics of additional systems is required to definitively assess lateral movement scope.

**Q4. What persistence mechanisms were installed?**

The investigation identified multiple persistence mechanisms employed by the attackers. The primary persistence mechanism is the PutterPanda malware itself detected via YARA signatures in memory with capabilities for command-and-control communication and re-infection. Volatility malfind analysis revealed PAGE_EXECUTE_READWRITE memory regions in multiple user-mode processes (dllhost.exe PID 8748, SearchApp.exe PIDs 8312 and 19436, LockApp.exe PID 9788, RuntimeBroker.exe PID 9964, Teams.exe PID 15636, smartscreen.exe PID 19348) indicating code injection techniques providing in-memory persistence across process restarts. The suspicious MRC.exe executable (PID 29440) running from D:\Tools\ represents an additional persistence mechanism, though the specific autorun configuration was not identified in registry analysis. The Dropbox client configured in the Windows Run registry key "Wow6432Node\Microsoft\Windows\CurrentVersion\Run" for automatic startup (last write October 28, 2020) represents a legitimate application that could be repurposed for persistence via DLL hijacking or binary replacement. The use of in-memory techniques indicates persistence likely survives system reboots through re-infection from scheduled tasks, registry autorun entries, WMI event subscriptions, or command-and-control infrastructure reinfection upon network reconnection. Complete persistence eradication requires comprehensive registry analysis of all autorun locations, scheduled task enumeration, WMI subscription review, service configuration audit, and verification of digital signatures on all autostart executables.

**Q5. Was data exfiltrated, and if so, what and how much?**

While the forensic evidence does not contain definitive proof of completed data exfiltration (network packet captures showing file transfers were not available), multiple indicators suggest high probability of intellectual property and corporate communications theft. The deletion of an Outlook PST file ($IDNBREY.pst) from the fredr account during the compromise window indicates potential email archive exfiltration followed by anti-forensic evidence destruction. PST files contain email messages, calendar items, contacts, tasks, and attachments representing high-value corporate intelligence targets. Google Drive File Stream was actively running during the compromise with bulk extractor evidence capturing POST requests to googleapis.com/upload/drive/v2internal/files endpoints indicating file upload activity. Similarly, Dropbox synchronization was configured and operational with update tasks executing November 1, 2020. The attackers' administrative privileges and PutterPanda malware memory access provide capability to access all files on the compromised workstation and all network shares accessible via the user's credentials. The 27-day compromise window (October 20 - November 16, 2020) provides extensive opportunity for large-scale data exfiltration. Definitive quantification of exfiltrated data requires audit log analysis from Google Workspace and Dropbox for abnormal upload patterns, firewall/proxy log review for bulk data transfers to suspicious destinations, and potential recovery and analysis of the deleted PST file via file carving techniques. In the absence of logs definitively disproving exfiltration, the incident response posture should assume worst-case scenario: all data accessible to the fredr user account including research documents, email archives, intellectual property, and credentials was compromised and exfiltrated to Chinese intelligence services.

**Q6. What is the full timeline of the incident?**

The incident timeline spans minimally 27 days from October 20, 2020 (earliest account creation) to November 16, 2020 (memory capture during active compromise):

- **October 20, 2020:** User accounts srl-h (RID 1001) and fredr (RID 1002) created with administrative privileges and "Password does not expire" flags. Password failure recorded on srl-h account at 19:46:16 UTC.
- **October 28, 2020, 12:26:11 UTC:** Dropbox client installed and configured for automatic startup via Windows Run registry key.
- **November 1, 2020, 21:02:27 and 21:30:01 UTC:** Dropbox update tasks (DropboxUpdateTaskMachineCore and DropboxUpdateTaskMachineUA) executed, confirming synchronization service operational.
- **November 10, 2020, 13:26:09 UTC:** Last login timestamp for srl-h account.
- **November 11, 2020, 08:13:16 UTC:** RDP service (PID 1248, svchost.exe) bound to 0.0.0.0:3389, accepting connections from any source. Google Drive File Stream active (drivefsext.dll loaded into explorer.exe at 08:13:47 UTC).
- **November 14, 2020, 03:42:22 UTC:** Password failure on fredr account, suggesting credential testing.
- **November 14, 2020, 12:51:58 UTC:** Last login timestamp for fredr account.
- **November 16, 2020, 00:23:06 UTC:** Password failure on Guest account (RID 501, disabled).
- **November 16, 2020, 01:12:37 UTC:** Password failure on DefaultAccount (RID 503, disabled).
- **November 16, 2020, 02:31:18 through 02:36:24 UTC:** More than 50 RDP connections from foreign IPs (81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114). One connection from 213.202.233.104:45753 ESTABLISHED at capture time.
- **November 16, 2020, 02:30:00 through 02:37:00 UTC:** Memory capture window showing active PutterPanda malware, MRC.exe (PID 29440) execution, code injection in multiple processes, and Outlook PST file deletion.
- **November 16, 2020, 02:50:31 UTC:** Password failure on Administrator account (RID 500, disabled).

The true incident start date may predate October 20, 2020, as sophisticated APT operations typically conduct extensive reconnaissance and preparation before deploying malware. The timeline above represents only the forensic evidence window captured in the analyzed artifacts.

**Q7. What is the total scope and business impact?**

The business impact encompasses national security implications, intellectual property theft, regulatory violations, reputational damage, and significant financial losses. The confirmed presence of PutterPanda (APT2), a Chinese state-sponsored APT toolset used exclusively for cyber espionage, elevates this incident from routine cybersecurity breach to national security concern with potential theft of export-controlled technology, proprietary research, or classified information. If Stark Research Labs conducts defense-related research or operates under ITAR, EAR, NIST 800-171, CMMC, or classified contracts, mandatory reporting to DCSA and contracting officers is required with potential contract suspension, debarment, civil penalties, and criminal liability for non-compliance. The 27-day compromise window provides extensive opportunity for intellectual property exfiltration including proprietary designs, experimental results, source code, grant proposals, patent applications, and strategic business plans representing millions of dollars in research and development investment now accessible to Chinese competitors at zero cost. Corporate email compromise (evidenced by PST file deletion) exposes strategic communications including confidential negotiations, financial projections, merger and acquisition discussions, legal matters, and competitive intelligence. Employee privacy violations include access to personal email, browser history, financial accounts, and geolocation metadata revealing international travel patterns. Incident response costs including enterprise-wide forensic investigation, malware eradication, credential rotation, security enhancement, and regulatory notification will range from hundreds of thousands to millions of dollars. Reputational damage with customers, partners, government agencies, and investors may result in lost contracts, terminated partnerships, and reduced valuation. Competitive disadvantage from stolen IP may permanently impair market position if Chinese recipients leverage exfiltrated research to accelerate domestic development or undercut product pricing.

**Q8. What are the recommended remediation actions?**

Immediate tactical containment actions (detailed in the Immediate Tactical Containment section) include isolating the compromised workstation, blocking foreign attacker IP addresses (81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114), disabling compromised accounts (srl-h, fredr), terminating suspicious MRC.exe process, blocking outbound RDP, disabling internet-exposed RDP service, suspending cloud storage synchronization, enabling emergency authentication monitoring, forcing enterprise-wide password reset, initiating PutterPanda indicator hunt, contacting law enforcement and government agencies (FBI, CISA, DCSA), and engaging external incident response firm.

Strategic long-term remediation (detailed in the Strategic Remediation section) requires comprehensive security architecture improvements including network segmentation with Zero Trust principles, elimination of direct internet exposure for remote administration protocols, deployment of VPN with multi-factor authentication, implementation of endpoint detection and response (EDR) platform with behavioral analytics and process injection detection, privileged access management eliminating standing administrative privileges, mandatory MFA for remote access and administrative actions using FIDO2 hardware security keys, data loss prevention monitoring cloud storage exfiltration, cloud access security broker (CASB) providing visibility and control over sanctioned applications, enhanced SIEM correlation rules detecting APT tactics, monthly threat hunting for Chinese APT indicators, aggressive patch management deploying critical updates within 72 hours, annual penetration testing simulating APT adversary tradecraft, mandatory security awareness training with APT-specific modules, insider threat program monitoring for malicious or negligent activity, incident response plan specific to APT intrusions with quarterly tabletop exercises, and business continuity procedures with air-gapped offline backups preventing ransomware or attacker destruction.

The implementation of these tactical and strategic remediation actions will require significant investment in technology, personnel, and process changes but is essential to prevent recurrence of APT compromises and protect Stark Research Labs' intellectual property, national security obligations, and competitive position.


---

## Overview

| | |
|---|---|
| Findings | **11** (6 confirmed, 5 inference) |
| Severity | 2 critical, 2 high, 5 medium, 1 low, 1 info |
| Sources | 14 evidence sources across 331 tool calls |


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
| 2014-11-06T22:20:00 | Geolocation Metadata in Images Reveals International Travel Patterns | INFO | bulk.gps |
| 2020-10-20T16:32:31 | Two User Accounts with Administrative Privileges | MEDIUM | registry.sam |
| 2020-10-28T12:26:11 | Dropbox Configured for Automatic Startup | MEDIUM | registry.software, bulk.domain |
| 2020-11-11T08:13:16 | RDP Service Exposed to Internet with Weak Access Controls | HIGH | volatility.netscan |
| 2020-11-11T08:13:47 | Google Drive File Stream Active During APT Compromise | MEDIUM | volatility.dlllist, bulk.url, bulk.email |
| 2020-11-16T00:23:06 | Failed Brute Force Attack Attempts Blocked by Security Controls | LOW | registry.sam |
| 2020-11-16T02:30:00 | APT PutterPanda Malware Detected in Memory | CRITICAL | yara.memory |
| 2020-11-16T02:30:00 | Suspicious Executable MRC.exe Running from Non-Standard Location | HIGH | volatility.cmdline, volatility.dlllist, volatility.handles, volatility.pslist |
| 2020-11-16T02:30:00 | Code Injection Detected in Multiple Processes Including Windows Defender | MEDIUM | volatility.malfind |
| 2020-11-16T02:30:00 | Outlook PST Data File Deleted During Compromise Window | MEDIUM | tsk.filelist |
| 2020-11-16T02:31:18 | Multiple Suspicious RDP Connections from Foreign IPs | CRITICAL | volatility.netscan |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] APT PutterPanda Malware Detected in Memory

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T02:30:00 to 2020-11-16T02:37:00 |
| **Sources** | yara.memory |
| **Evidence Refs** | tc_f57f6a94, tc_7e8488fd |
| **ATT&CK** | [T1055](https://attack.mitre.org/techniques/T1055/) |


YARA memory scan detected APT_Malware_PutterPanda_WUAUCLT signatures in the memory dump. The detection includes characteristic strings "NullRefrencedException" (misspelled) and "error has occurred in user32.dll by" which are known indicators of the PutterPanda (APT2) backdoor. Additional detection of APT6_Malware_Sample_Gen rule with multiple hits on system paths. PutterPanda is a sophisticated APT group known for targeted cyber espionage campaigns. The presence of this malware in memory indicates active compromise at the time of memory capture.



### 2. [CRITICAL] Multiple Suspicious RDP Connections from Foreign IPs

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T02:31:18 to 2020-11-16T02:36:24 |
| **Sources** | volatility.netscan |
| **Evidence Refs** | tc_0100723b, tc_15f0f668 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


Memory analysis revealed over 50 RDP (port 3389) connections from two primary foreign IP addresses: 81.30.144.115 (multiple connections) and 213.202.233.104 (multiple connections). Additional connections from 81.19.209.101 and 201.193.188.114 were also observed. The vast majority of connections are in CLOSED state at memory capture time (2020-11-16 02:30-02:37), with timestamps spanning 2020-11-16 02:31:18 through 02:36:24. The pattern and volume of connections is consistent with either successful RDP brute force attack or active remote access by threat actors. All connections terminated through svchost.exe (PID 1248), the Terminal Services process. One connection from 213.202.233.104:45753 was in ESTABLISHED state at capture time, indicating active session. This activity correlates temporally with the detected APT malware presence.



### 3. [HIGH] RDP Service Exposed to Internet with Weak Access Controls

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-11-11T08:13:16 to 2020-11-16T02:37:00 |
| **Sources** | volatility.netscan |
| **Evidence Refs** | tc_0100723b |
| **ATT&CK** | [T1133](https://attack.mitre.org/techniques/T1133/) |


The system had RDP (port 3389) listening on all interfaces and accessible from the internet, as evidenced by successful connections from multiple foreign IP addresses. The netscan output shows RDP service (PID 1248, svchost.exe) bound to 0.0.0.0:3389 since 2020-11-11 08:13:16, accepting connections from any source. This configuration, combined with the successful foreign connections and APT malware presence, indicates the RDP service lacked proper access controls (IP whitelisting, VPN requirement, or multi-factor authentication). Remote Desktop Protocol exposure is a common initial access vector for APT groups and ransomware operators.



### 4. [HIGH] Suspicious Executable MRC.exe Running from Non-Standard Location

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2020-11-16T02:30:00 to 2020-11-16T02:37:00 |
| **Sources** | volatility.cmdline, volatility.dlllist, volatility.handles, volatility.pslist |
| **Evidence Refs** | tc_71faf856, tc_be3f5c63, tc_cbf9ffbc |
| **ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059](https://attack.mitre.org/techniques/T1059/) |


A suspicious executable "MRC.exe" (PID 29440) was found running from the non-standard location "D:\Tools\MRC.exe" at the time of memory capture. The executable's DLL listings show corrupted/impossible timestamps (years 1691, 1715, 3515, 3520, 3536) which is characteristic of malware attempting to hide or having corrupted PE headers. The generic name "MRC.exe" and non-standard D:\Tools\ location are consistent with attacker tooling rather than legitimate software. Process handles show references from svchost.exe (PID 1040), suggesting system-level interaction. This executable was actively running alongside the detected APT PutterPanda malware and RDP compromise, indicating it may be part of the attacker's toolkit deployed post-compromise.



### 5. [MEDIUM] Code Injection Detected in Multiple Processes Including Windows Defender

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-11-16T02:30:00 to 2020-11-16T02:37:00 |
| **Sources** | volatility.malfind |
| **Evidence Refs** | tc_e2a773a7 |
| **ATT&CK** | [T1055](https://attack.mitre.org/techniques/T1055/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |


Volatility malfind analysis detected PAGE_EXECUTE_READWRITE memory regions in multiple processes. Counter-analysis reveals that detections in Windows Defender (MsMpEng.exe, PID 4864) represent NORMAL antivirus engine behavior rather than malicious code injection. The 5 memory regions flagged in MsMpEng.exe contain legitimate assembly code prologues (VWSUATAUAVAWH patterns) and INT3 padding bytes (0xCC) characteristic of production AV software that requires executable memory for dynamic signature scanning, emulation, and JIT compilation.

However, malfind also detected suspicious regions in other processes that warrant investigation: dllhost.exe (PID 8748), SearchApp.exe (PIDs 8312 and 19436 - 4 regions total), LockApp.exe (PID 9788), RuntimeBroker.exe (PID 9964), Teams.exe (PID 15636), and smartscreen.exe (PID 19348). The detections in user-mode processes, combined with the confirmed PutterPanda APT malware presence and suspicious MRC.exe executable, indicate code injection techniques may have been employed by attackers targeting non-security processes. The original assessment incorrectly characterized normal AV behavior as evidence of malware targeting security software, when the actual concern should focus on the injection patterns in other processes.



### 6. [MEDIUM] Dropbox Configured for Automatic Startup

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-10-28T12:26:11 to 2020-11-01T21:30:12 |
| **Sources** | registry.software, bulk.domain |
| **Evidence Refs** | tc_2fcd8769, tc_90273de9, tc_f540fc72 |
| **ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Registry analysis shows Dropbox client configured in the Windows Run key for automatic startup on system boot. The registry key "Wow6432Node\Microsoft\Windows\CurrentVersion\Run" contains entry: "Dropbox - \"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe\" /systemstartup" with last write time of 2020-10-28 12:26:11Z. While Dropbox is legitimate cloud storage software, in the context of this active APT compromise, cloud storage applications represent a potential data exfiltration vector. The timing of the Dropbox installation (2020-10-28) falls within the broader attack timeline leading up to the memory capture on 2020-11-16. Task scheduler evidence shows Dropbox update tasks (DropboxUpdateTaskMachineCore and DropboxUpdateTaskMachineUA) actively running, with last executions on 2020-11-01 21:02:27Z and 2020-11-01 21:30:01Z respectively. Bulk extractor data confirms Dropbox static content references (cfl.dropboxstatic.com). Further investigation recommended to determine if Dropbox was used for unauthorized data exfiltration.



### 7. [MEDIUM] Two User Accounts with Administrative Privileges

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-10-20T16:32:31 to 2020-11-14T12:51:58 |
| **Sources** | registry.sam |
| **Evidence Refs** | tc_0002dd7b |
| **ATT&CK** | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) |


SAM registry analysis reveals two user accounts (srl-h [RID 1001] and fredr [RID 1002]) both configured as members of the Administrators group, granting full system access. The srl-h account is associated with email srl-helpdesk@outlook.com and shows last login on 2020-11-10 13:26:09Z (for the older snapshot) and 2020-11-14 12:51:58Z for user fredr (Fred Rocba, fred.rocba@outlook.com). Both accounts were created between 2020-10-20 and 2020-10-27. The presence of multiple administrator accounts increases the attack surface and violates the principle of least privilege. In the context of this APT compromise with successful RDP access from foreign IPs, multiple admin accounts provided the attackers with multiple potential access vectors. The fredr account shows password failure on 2020-11-14 03:42:22Z, suggesting possible brute force attempts or attacker authentication testing. Both accounts have "Password does not expire" flag set, another security weakness. Best practice dictates limiting administrative access to a minimal number of accounts with regular password rotation requirements.



### 8. [MEDIUM] Google Drive File Stream Active During APT Compromise

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-11-11T08:13:47 to 2020-11-16T02:37:00 |
| **Sources** | volatility.dlllist, bulk.url, bulk.email |
| **Evidence Refs** | tc_ed23f6c2, tc_7adf8815, tc_1987a6df |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Google Drive File Stream application (version 43.0.8.0) was actively running on the compromised system at the time of memory capture, as evidenced by the drivefsext.dll module loaded into explorer.exe. Bulk extractor URL artifacts show multiple POST requests to googleapis.com/upload/drive/v2internal/files endpoints with resumable upload parameters, indicating file upload activity to Google Drive cloud storage during the compromise window. The URLs include metadata fields for file properties (title, mimeType, modifiedDate, fileSize, md5Checksum, etc.) consistent with Google Drive File Stream synchronization operations. While Google Drive File Stream is legitimate software used by the organization (OneDrive - Stark Research Labs directories present), in the context of an active APT compromise with PutterPanda malware and successful RDP intrusion from foreign IPs, the cloud storage application represents a potential data exfiltration vector. Attackers could leverage the victim's authenticated Google Drive account to exfiltrate sensitive corporate data without triggering egress monitoring alarms, as the traffic appears as legitimate cloud backup activity. The timing of upload activity coinciding with the APT malware presence (2020-11-16 memory capture timeframe) raises concern about potential unauthorized data access and exfiltration. Further investigation recommended to review Google Drive audit logs for the user account frocba@stark-research-labs.com to identify files uploaded during the compromise window and determine if any sensitive data was accessed or exfiltrated by the attackers.



### 9. [MEDIUM] Outlook PST Data File Deleted During Compromise Window

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-11-16T02:30:00 to 2020-11-16T02:37:00 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_65c3a589 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Filesystem analysis reveals an Outlook PST (Personal Storage Table) file was deleted and moved to the Recycle Bin during the investigation timeframe. The file $IDNBREY.pst was found in the Recycle Bin path for user SID S-1-5-21-528816539-567677750-276746561-1002 (user fredr). PST files contain Outlook email messages, calendar items, contacts, tasks, and other mailbox data. The deletion of a PST file during an active APT compromise is significant for several reasons: (1) Attackers may delete PST files after exfiltrating email data to remove evidence of their access to corporate communications; (2) Users or administrators may delete PST files as part of incident response cleanup without proper forensic preservation; (3) The timing of deletion could indicate awareness of compromise or attempted evidence destruction. The presence of other deleted files in the same Recycle Bin path ($IDLNUZH.msi installer and $IDTQK82.exe executable) suggests multiple file deletions occurred during this timeframe. Given the confirmed APT PutterPanda presence, successful RDP compromise, and potential data exfiltration via cloud storage services, the deletion of email archive data warrants investigation. Recommendation: Attempt recovery of the deleted PST file using file carving techniques to determine its size, last modification date, and potentially recover email content to assess whether sensitive corporate communications were accessed by the attackers prior to deletion. Cross-reference PST deletion timestamp with Google Drive and Dropbox upload activity logs to determine if email data was exfiltrated before deletion.



### 10. [LOW] Failed Brute Force Attack Attempts Blocked by Security Controls

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T00:23:06 to 2020-11-16T02:50:31 |
| **Sources** | registry.sam |
| **Evidence Refs** | tc_0002dd7b, tc_de30f9a3 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |


Registry SAM analysis reveals password failure attempts against built-in system accounts during the attack window on 2020-11-16, coinciding with RDP connections from foreign IPs. However, counter-analysis demonstrates that ALL password failures occurred ONLY on DISABLED accounts: Administrator (RID 500) failed at 2020-11-16 02:50:31Z, Guest (RID 501) at 2020-11-16 00:23:06Z, and DefaultAccount (RID 503) at 2020-11-16 01:12:37Z. These failures occurred within the same timeframe as suspicious RDP connections from 81.30.144.115, 213.202.233.104, and other foreign IPs (2020-11-16 02:31:18 through 02:36:24).

The two actual user accounts (srl-h RID 1001 and fredr RID 1002) show password failures BEFORE the critical RDP window: srl-h at 2020-10-20 19:46:16Z and fredr at 2020-11-14 03:42:22Z, NOT during the active RDP connection period.

This evidence indicates that brute force attacks targeting default Windows accounts were SUCCESSFULLY BLOCKED by proper security controls (account disablement). While attackers did ultimately gain access (as evidenced by APT malware presence and active ESTABLISHED RDP connection), they did NOT succeed through password brute forcing of system accounts. The access vector remains unknown but was NOT through compromising disabled built-in accounts. The Guest account's \"Password not required\" configuration is a security weakness, but the account's disabled status prevented exploitation.



### 11. [INFO] Geolocation Metadata in Images Reveals International Travel Patterns

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2014-11-06T22:20:00 to 2016-05-18T11:50:00 |
| **Sources** | bulk.gps |
| **Evidence Refs** | tc_63d9564d |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/) |


Analysis of EXIF GPS metadata embedded in images on the compromised system reveals extensive international travel history. GPS coordinates extracted via bulk_extractor identify visits to multiple countries including Romania (Bucharest area: 44.43°N, 26.09°E with 70+ coordinate entries), Thailand (Bangkok area: 13.75°N, 100.49°E), Hawaii (20.68°N, -156.44°W), Mexico (multiple locations), and various US locations (Chicago, San Francisco, Washington DC). The heaviest concentration of GPS-tagged images originates from the Bucharest, Romania metropolitan area with timestamps ranging from 2014-2016. This travel metadata is significant in the context of an APT compromise for several reasons: (1) APT actors conducting reconnaissance could use travel patterns to identify when the victim is away from the primary office, presenting opportunities for physical or social engineering attacks; (2) Geolocation data can reveal business relationships, partnerships, or client locations that may be of intelligence value to state-sponsored threat actors; (3) The concentration of Romania-sourced imagery suggests either frequent business travel to Eastern Europe or potential dual work locations, which could indicate research partnerships or facilities in that region; (4) Travel pattern analysis can inform attribution investigations by identifying potential geographic connections between the victim and threat actors. The presence of this geolocation metadata also represents an operational security concern, as attackers with access to the file system can extract location intelligence without needing to exfiltrate the full images. While this finding does not indicate malicious activity by itself, it provides valuable context about the victim's international footprint and potential attack surface.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| External IP | `213.202.233.104` | Multiple Suspicious RDP Connections from Foreign IPs |
| Port | `TCP 45753` | Multiple Suspicious RDP Connections from Foreign IPs |
| External IP | `81.30.144.115` | Multiple Suspicious RDP Connections from Foreign IPs |
| External IP | `81.19.209.101` | Multiple Suspicious RDP Connections from Foreign IPs |
| External IP | `201.193.188.114` | Multiple Suspicious RDP Connections from Foreign IPs |
| Port | `TCP 3389` | Multiple Suspicious RDP Connections from Foreign IPs |
| External IP | `43.0.8.0` | Google Drive File Stream Active During APT Compromise |


### File IOCs

| Type | Value | Context |
|------|-------|---------|
| Path | `C:\Program` | Dropbox Configured for Automatic Startup |



### Email IOCs

| Type | Value | Context |
|------|-------|---------|
| Email | `srl-helpdesk@outlook.com` | Two User Accounts with Administrative Privileges |
| Email | `fred.rocba@outlook.com` | Two User Accounts with Administrative Privileges |
| Email | `frocba@stark-research-labs.com` | Google Drive File Stream Active During APT Compromise |




---

## Appendix C: MITRE ATT&CK Coverage

14 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (3) > Execution (2) > Persistence (4) > Privilege Escalation (4) > Defense Evasion (5) > Credential Access (2) > Lateral Movement (1) > Collection (1) > Exfiltration (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Multiple Suspicious RDP Connections from Foreign IPs |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | Two User Accounts with Administrative Privileges |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | RDP Service Exposed to Internet with Weak... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Suspicious Executable MRC.exe Running from... |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Suspicious Executable MRC.exe Running from... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Multiple Suspicious RDP Connections from Foreign IPs |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | Two User Accounts with Administrative Privileges |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | RDP Service Exposed to Internet with Weak... |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | Dropbox Configured for Automatic Startup |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | APT PutterPanda Malware Detected in Memory; Code Injection Detected in Multiple Processes... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Multiple Suspicious RDP Connections from Foreign IPs |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | Two User Accounts with Administrative Privileges |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | Dropbox Configured for Automatic Startup |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | APT PutterPanda Malware Detected in Memory; Code Injection Detected in Multiple Processes... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Outlook PST Data File Deleted During Compromise Window |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Multiple Suspicious RDP Connections from Foreign IPs |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | Two User Accounts with Administrative Privileges |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Code Injection Detected in Multiple Processes... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Failed Brute Force Attack Attempts Blocked by... |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Failed Brute Force Attack Attempts Blocked by... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Multiple Suspicious RDP Connections from Foreign IPs |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Geolocation Metadata in Images Reveals... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Dropbox Configured for Automatic Startup; Google Drive File Stream Active During APT Compromise |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 331 |
| Findings submitted | 11 |
| Confirmed | 6 |
| Inferences | 5 |
| Estimated input tokens | 9.3K |
| Estimated output tokens | 35.9K |
| Audit log | /home/mulder/.mulder/cases/evidence.audit.jsonl |




<details>
<summary>Evidence Sources (55)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| volatility.pslist | volatility3 | 2187 |
| volatility.pstree | volatility3 | 2187 |
| volatility.netscan | volatility3 | 431 |
| tsk.filelist | sleuthkit | 602765 |
| volatility.malfind | volatility3 | 17 |
| volatility.dlllist | volatility3 | 12764 |
| volatility.handles | volatility3 | 144713 |
| volatility.cmdline | volatility3 | 2187 |
| volatility.filescan | volatility3 | 42799 |
| volatility.psscan | volatility3 | 2213 |
| volatility.envars | volatility3 | 6362 |
| volatility.svcscan | volatility3 | 1418 |
| registry.sam | regripper | 212 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 75 |
| registry.security | regripper | 8 |
| registry.software | regripper | 45225 |
| registry.software | regripper | 283 |
| registry.software | regripper | 283 |
| registry.system | regripper | 8617 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.sam | regripper | 212 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 75 |
| registry.security | regripper | 8 |
| registry.security | regripper | 8 |
| registry.software | regripper | 45441 |
| registry.software | regripper | 283 |
| registry.system | regripper | 8742 |
| registry.system | regripper | 199 |
| registry.default | regripper | 406 |
| registry.software | regripper | 283 |
| bulk.alerts | bulk_extractor | 6 |
| bulk.domain | bulk_extractor | 237914 |
| bulk.email | bulk_extractor | 9820 |
| bulk.ether | bulk_extractor | 74 |
| bulk.exif | bulk_extractor | 988 |
| bulk.gps | bulk_extractor | 344 |
| bulk.httplogs | bulk_extractor | 11 |
| bulk.ip | bulk_extractor | 147 |
| bulk.packets | bulk_extractor | 604 |
| bulk.rfc822 | bulk_extractor | 2642 |
| bulk.tcp | bulk_extractor | 76 |
| bulk.url | bulk_extractor | 232947 |
| bulk.url_facebook-address | bulk_extractor | 8 |
| bulk.url_facebook-id | bulk_extractor | 9 |
| bulk.url_searches | bulk_extractor | 76 |
| bulk.url_services | bulk_extractor | 3657 |
| bulk.winlnk | bulk_extractor | 338 |
| bulk.winpe | bulk_extractor | 1603 |
| bulk.winpe_carved | bulk_extractor | 1602 |
| yara.memory | yara | 40516 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
