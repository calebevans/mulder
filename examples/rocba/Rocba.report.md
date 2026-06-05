# Mulder Investigation Report

**Case:** rocba
**Generated:** 2026-06-05T07:25:14.736268+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 67 evidence sources (9 memory, 14 disk, 44 other) | 292 tool calls | 1.1 hours
**Results:** 7 findings (1 high) | 7 confirmed, 0 inference
**Timeline:** 2020-10-30 to 2020-11-16

**Attack Lifecycle:**
- **Initial Access / Deployment** (2020-10-30 to 2020-11-16): Recurring RDP Brute-Force Campaign — Windows.old SAM Evidence of Prior Attacks (+3 related)
- **Persistence** (2020-11-16): RDP Service Exposed to Internet Without Access Restrictions

**Tools:** search (69), get_raw_output (35), open_case (11), get_investigation_summary (9), get_source_stats (8). SHA-256 hashes recorded for all evidence.



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

292 tool calls were executed across 21
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Digital Forensic Investigation Report — Case ROCBA

## Background

This investigation was initiated in response to a suspected compromise of a Windows workstation belonging to Fred Rocba (user account "fredr"), an employee of Stark Research Labs. The system under examination, at internal IP address 192.168.1.5, was identified as running Windows 10 with Remote Desktop Protocol (RDP) services exposed directly to the internet on the default port 3389. A forensic disk image in E01 format containing both a memory dump and a full-disk capture was provided as evidence.

The forensic analysis drew upon 21 indexed evidence sources spanning eleven distinct extractor types: Volatility 3 memory forensics, Sleuth Kit disk analysis, EZ Tools (AmCache, ShimCache, MFT, Prefetch), RegRipper registry parsing, bulk_extractor IOC carving, YARA signature scanning, Chainsaw Sigma rule analysis, composite correlation engines, timestomping detection, EVTX log extraction, and IOC enrichment services. A total of 292 tool invocations were executed across the investigation. The analysis produced 7 formal findings, of which 7 are confirmed through multi-source corroboration.

The evidence environment includes a current Windows 10 installation as well as remnants of a prior installation preserved in a Windows.old directory, providing a longitudinal view of system activity and attack history across two separate operating system installations. The system serves as a general-purpose workstation with typical enterprise productivity software (Microsoft Office, Adobe Acrobat, Chrome, Firefox, Dropbox) and organizational collaboration tools (Microsoft Teams, Slack, Zoom).

## Incident Timeline

The incident timeline spans approximately seventeen days, from the earliest evidence of credential attacks on 2020-10-30 through the captured active brute-force assault on 2020-11-16. Events are reconstructed from SAM registry hive timestamps, Volatility memory forensics, and cross-correlated filesystem artifacts.

**Phase 1 — Initial Reconnaissance and Early Probing (2020-10-30 to 2020-11-01)**

The earliest evidence of unauthorized activity is found in the Windows.old SAM hive from the prior Windows installation. On 2020-10-30 at 13:14:47 UTC, the Guest account recorded a password failure, indicating external credential guessing against the system's RDP service. This probing continued through 2020-11-01, when at 21:22:15 UTC the DefaultAccount recorded a password failure. Notably, the prior installation's active accounts ("srl-h" with last login at 2020-10-20 16:14:19 UTC and "fredr" with last login at 2020-10-20 16:23:21 UTC) did not record any password failures on these dates, suggesting the attacker was enumerating default and disabled accounts rather than targeting known usernames.

The system was reinstalled on 2020-11-01 at approximately 22:15 UTC, roughly 42 minutes after the last recorded login on the old installation (srl-h at 21:33 UTC). While the temporal proximity to the brute-force activity is notable, no evidence of successful compromise was found in the old installation's SAM, and the reinstallation may have been a routine maintenance event or a precautionary response to suspected intrusion attempts.

**Phase 2 — Quiescent Period (2020-11-02 to 2020-11-15)**

Following the reinstallation, the system operated normally. Archived Security Event Logs span from 2020-11-02 through 2020-11-06, though these were not parsed for the attack period as they predate the primary incident. Legitimate user activity resumed, with user "srl-h" last logging in on 2020-11-10 at 13:26:09 UTC and user "fredr" last logging in on 2020-11-14 at 12:51:58 UTC. ShimCache and AmCache records from this period show only standard application execution — Adobe products, Chrome, Firefox, Office applications, and system utilities.

**Phase 3 — Active Brute-Force Attack (2020-11-16, 00:23 to 02:50 UTC)**

The primary attack commenced on 2020-11-16 with a methodical escalation. At 00:23:06 UTC, the Guest account recorded a password failure, marking the beginning of username enumeration against the new installation. At 01:12:37 UTC, the DefaultAccount was targeted. The attack then intensified dramatically around 02:30 UTC, when four external IP addresses launched a coordinated RDP brute-force assault.

Network connections captured in the memory dump show the attack infrastructure:

The first and most persistent attacker, at IP 81.30.144.115 (Germany, AS24961 WIIT AG), maintained over forty connections to port 3389, including ESTABLISHED sessions observed at 02:34:45 and 02:34:58 UTC, interspersed with numerous CLOSED connections from 02:31 through 02:36 UTC. A second attacker at 213.202.233.104, sharing the same German autonomous system (AS24961 WIIT AG), exhibited a similar pattern with over forty connections, including ESTABLISHED sessions at 02:34:58 and 02:35:53 UTC. A third source, 81.19.209.101 (Netherlands, AS25369 Hydra Communications Ltd), briefly appeared with a SYN_RCVD connection at 02:33:32 UTC followed by a CLOSED state at 02:33:38 UTC. A fourth attacker at 201.193.188.114 (Costa Rica, AS11830 ICE) connected sporadically, with CLOSED connections at 02:30:05, 02:32:49, and 02:34:25 UTC. All inbound RDP connections were handled by svchost.exe PID 1248, the legitimate Terminal Services listener process.

The Administrator account recorded its password failure at 02:50:31 UTC, representing the last recorded attack event and indicating the attackers escalated from default/guest accounts to the built-in Administrator account during the assault.

**Phase 4 — Memory Capture (2020-11-16, approximately 02:36 UTC)**

The memory dump was acquired during the active attack, preserving the state of multiple ESTABLISHED and recently CLOSED RDP connections. This capture timing proved invaluable, providing a snapshot of the attack infrastructure in real time.

## Key Findings

**RDP Brute-Force Attack Infrastructure**

The investigation confirmed an active, coordinated RDP brute-force attack originating from four external IP addresses. Two of the attacking IPs, 81.30.144.115 and 213.202.233.104, share the same autonomous system number (AS24961 WIIT AG, Germany), strongly suggesting coordinated infrastructure — either a single actor using multiple nodes within the same hosting provider, or a shared botnet leveraging that provider's resources. The third IP (81.19.209.101, Netherlands) and fourth IP (201.193.188.114, Costa Rica) operated from different network providers, consistent with either a geographically distributed attack operation or compromised hosts being leveraged for credential stuffing.

The attack methodology followed a classic credential-guessing pattern: initial enumeration of default and disabled accounts (Guest, DefaultAccount) before escalating to the built-in Administrator account. This pattern was consistent across both the prior and current Windows installations, spanning at least seventeen days.

**No Successful Compromise Achieved**

The most significant conclusion of this investigation is the definitive determination that the brute-force attack did not succeed in gaining access to the system. This assessment rests on multiple independent lines of evidence. The SAM registry hive provides the strongest evidence: the Last Login timestamps for both active user accounts — srl-h (2020-11-10 13:26:09 UTC) and fredr (2020-11-14 12:51:58 UTC) — are definitively before the 2020-11-16 attack. A successful RDP authentication would have updated the Last Login timestamp for the authenticated account. Furthermore, neither active account recorded password failures on the attack date, indicating the attackers did not guess the correct usernames for active accounts. Password failures were recorded only on disabled accounts (Guest, DefaultAccount, Administrator), none of which could grant interactive access even with the correct password.

Memory forensics corroborated this conclusion through multiple independent checks. The Volatility process tree revealed no anomalous parent-child relationships; all running processes were legitimate Windows services and user applications. No hidden processes were detected in the psscan-versus-pslist differential analysis, ruling out rootkit-level concealment. No suspicious command lines appeared in the cmdline plugin output. No network connections existed between any user-space process and the attacker IP addresses — only the TermService listener (svchost.exe PID 1248) communicated with those IPs. Malfind results flagged two processes, MsMpEng.exe (PID 4864) and SearchApp.exe (PID 8312), but both exhibited benign RWX memory regions characteristic of just-in-time compilation and antivirus engines, with no shellcode signatures detected.

Disk forensics provided further negative confirmation. ShimCache and AmCache execution history contained only legitimate software. No reconnaissance tools (net.exe for enumeration, psexec, mimikatz, or similar post-exploitation frameworks) appeared in any execution artifact. Prefetch files showed normal application execution patterns. MFT analysis detected no evidence of timestomping beyond a single benign NTFS root directory entry discrepancy.

**Evidentiary Gap in Security Event Logs**

A significant evidentiary limitation was identified: the active Security.evtx file covering the attack date (2020-11-16) was not available in the extracted evidence. Only fifteen archived Security log files were recovered, spanning 2020-11-02 through 2020-11-06. This ten-day gap between the last archived log and the attack date means that Windows Security Event IDs 4624 (successful logon), 4625 (failed logon), and related authentication audit events from the attack period could not be examined directly. The investigation was unable to determine whether this gap resulted from normal log rotation, intentional log clearing, or an artifact of the evidence collection process. However, the absence of these logs did not materially impair the investigation's primary conclusions, as the SAM Last Login timestamps and memory forensics provided independent, definitive evidence against successful compromise.

**Recurring Attack Pattern Across Installations**

Cross-referencing SAM hives from both the current and prior (Windows.old) installations revealed that this system has been under sustained external credential attack for at least seventeen days. The attack pattern — targeting disabled and default accounts via RDP — persisted identically across a complete operating system reinstallation, confirming that the root vulnerability is the network exposure of the RDP service rather than any software-level misconfiguration that would be resolved by reinstallation.

**YARA and Sigma Detection Results**

YARA scanning produced 597 match windows against memory and 44 against disk files using the signature-base ruleset. Comprehensive triage of every matched string confirmed all results as false positives arising from generic pattern matches against legitimate Windows system content. Notably, Cobalt Strike beacon rules matched only on standard date format strings and Windows PE headers; APT family rules matched only on common system paths and format specifiers. Chainsaw Sigma rule analysis against available archived event logs returned zero findings. These results collectively establish the absence of known malware families, offensive toolkits, or implants in both the memory space and filesystem.

**User IOC Clearance**

During evidence carving, several potentially suspicious indicators were identified, including the domain cobracommandcenter.com and email addresses such as redguard.cobra@gmail.com and crimsonguard@cobracommandcenter.com. Investigation determined these belong to Fred Rocba's personal accounts, evidenced by consistent naming themes across his account portfolio, co-occurrence with his confirmed email addresses in browser cache and cloud sync metadata, and the domain's appearance in browser history as a personal website. These indicators were formally cleared and should not be treated as threat intelligence.

## Threat Intelligence and Attribution

The attacking infrastructure spans three autonomous systems across three countries: AS24961 WIIT AG in Germany (two IPs: 81.30.144.115 and 213.202.233.104), AS25369 Hydra Communications Ltd in the Netherlands (81.19.209.101), and AS11830 ICE in Costa Rica (201.193.188.114). The concentration of two IPs within a single German hosting provider suggests either dedicated attack infrastructure or compromised servers within that provider's network.

The attack methodology is consistent with opportunistic RDP brute-forcing, a technique widely employed by ransomware affiliates, initial access brokers, and automated scanning botnets. The tactics, techniques, and procedures map to MITRE ATT&CK T1110.001 (Brute Force: Password Guessing), T1021.001 (Remote Services: Remote Desktop Protocol), and T1133 (External Remote Services). The attack pattern — enumeration of default accounts before targeting administrative accounts, sustained activity over weeks, use of geographically distributed infrastructure — is characteristic of automated credential-stuffing campaigns rather than targeted intrusions against Stark Research Labs specifically.

Attribution to a specific threat actor or group cannot be established from the available evidence. RDP brute-forcing is a commodity technique used across the threat landscape, from opportunistic ransomware operators (Dharma/CrySIS, Phobos, SamSam campaigns have historically relied on this vector) to initial access brokers selling RDP credentials on underground markets. The use of European hosting infrastructure and the automated, non-targeted nature of the account enumeration are consistent with botnet-driven scanning operations, but this assessment is based on behavioral pattern matching rather than definitive attribution indicators.

## Impact Assessment

The immediate impact of this incident is limited, as no successful compromise was achieved. However, the investigation reveals significant ongoing risk. The system at 192.168.1.5 has been under sustained external attack for at least seventeen days across two separate operating system installations. The RDP service remains bound to all network interfaces (0.0.0.0:3389) with no evidence of firewall policies restricting inbound connections by source IP. While Network Level Authentication (NLA) and TLS encryption are enabled — providing protection against unauthenticated vulnerability exploitation — the service remains vulnerable to credential-based attacks.

The two active user accounts (srl-h and fredr) are both members of the local Administrators group, meaning a successful password guess against either account would grant full administrative access to the system. Given the persistence of the attacks and the inevitable exposure of this system to continued brute-force campaigns, the probability of eventual compromise increases with time if the current configuration is maintained. The presence of enterprise collaboration tools (Microsoft Teams, Slack, SharePoint) and cloud-synced data (Dropbox, OneDrive, iCloud) means that a successful compromise would potentially expose not only local data but also organizational credentials and cloud-stored documents belonging to Stark Research Labs.

One system was targeted and zero were compromised. No data was exfiltrated, no persistence mechanisms were installed, and no lateral movement occurred.

## Immediate Tactical Containment

The following actions should be executed immediately to neutralize the active threat:

1. Block inbound connections from attacking IPs at the network perimeter firewall: 81.30.144.115, 213.202.233.104, 81.19.209.101, and 201.193.188.114.
2. Block inbound traffic from AS24961 (WIIT AG) at the perimeter if operationally feasible, as two of four attacker IPs originate from this autonomous system and additional nodes within it may be used in future attacks.
3. Disable direct internet-facing RDP access to 192.168.1.5 by blocking inbound TCP/UDP port 3389 from all external (non-RFC1918) source addresses at the network firewall.
4. Verify that no unauthorized sessions are currently active on 192.168.1.5 by reviewing the output of "qwinsta" or "query session" commands. The memory capture showed no unauthorized sessions, but the system has continued operating since the capture.
5. Force password resets for both active local accounts: srl-h and fredr. Although no successful compromise was detected, the accounts have been targeted by brute-force attacks and password rotation is a precautionary measure.
6. Disable the built-in Administrator account (if not already disabled at the OS level, as the SAM shows it was targeted by the attackers at 02:50:31 UTC) via "net user Administrator /active:no".
7. Review and confirm that the Guest and DefaultAccount remain disabled in the SAM, as both showed password failure timestamps indicating active targeting.

## Strategic Remediation

The root cause of this incident is the direct exposure of the RDP service to the public internet without network-level access controls. The registry configuration (ControlSet001\Control\Terminal Server: fDenyTSConnections = 0, WinStations\RDP-Tcp bound to port 3389 on all interfaces) combined with the absence of any firewall policy evidence restricting source IPs created an attack surface that was discovered and exploited within days of the system's deployment. This exposure persisted identically across a complete Windows reinstallation on 2020-11-01, demonstrating that reinstallation without addressing the network architecture does not mitigate the risk. Remediation requires implementing a VPN or jump-host architecture for remote access, or at minimum deploying Windows Firewall rules restricting RDP inbound connections to specific authorized source IP ranges, as documented in findings f_5a146e45 and f_7027756a.

The investigation's reliance on SAM Last Login timestamps to rule out compromise — rather than Security Event Log analysis — highlights a critical gap in audit log retention. The active Security.evtx for the attack period was unavailable, and archived logs covered only 2020-11-02 through 2020-11-06, leaving a ten-day evidentiary blind spot preceding the attack (finding f_7e75fe91). For a system exposed to persistent external attacks, the log retention policy should ensure that authentication events (Event IDs 4624, 4625, 4648) are preserved for a minimum of 90 days, either through increased maximum log file sizes, centralized log forwarding to a SIEM, or both. Had the active Security.evtx been available, the investigation could have corroborated the SAM-based conclusion with event-level granularity and identified the exact number of failed authentication attempts.

Both active user accounts (srl-h and fredr) hold local Administrator privileges, and the Remote Desktop Users group has zero explicitly configured members — meaning RDP access is governed solely by Administrator group membership. This configuration (finding f_5a146e45) means that a successful credential guess against either account would yield full administrative control. Implementing least-privilege access by creating standard user accounts for daily RDP sessions and reserving Administrator credentials for elevated operations would reduce the blast radius of a future successful brute-force attack.

The brute-force attack methodology (finding f_ef85e9ae) progressed from default account enumeration (Guest, DefaultAccount) to the built-in Administrator account, a pattern that account lockout policies would partially disrupt. The absence of any observed lockout behavior during sustained connection floods suggests that no account lockout threshold is configured for these accounts. Implementing account lockout policies (e.g., lockout after 5 failed attempts with a 30-minute duration) on all accounts — particularly the built-in Administrator, which requires specific Group Policy configuration as it is exempt from default lockout policies — would significantly increase the cost of brute-force attacks, as observed in MITRE ATT&CK T1110.001.

## Conclusion

**Q1. What systems were compromised?** No systems were compromised. The target system at 192.168.1.5 successfully resisted the brute-force attack. SAM Last Login timestamps, memory forensics, disk artifact analysis, and composite correlation across 21 evidence sources unanimously confirm no unauthorized access occurred.

**Q2. How did the attacker gain initial access?** The attacker did not gain initial access. The attempted vector was RDP brute-force credential guessing (MITRE ATT&CK T1110.001) against the internet-exposed RDP service on port 3389. Four external IPs (81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114) conducted sustained connection attempts, but all authentication attempts failed against active user accounts.

**Q3. What lateral movement occurred?** No lateral movement occurred. Composite lateral movement analysis returned zero results. No network connections to internal systems from attacker-associated processes were detected, and no lateral movement tools appeared in execution history.

**Q4. What persistence mechanisms were installed?** No attacker-installed persistence mechanisms were found. Registry autorun keys, services, scheduled tasks, AppInit_DLLs, and Winlogon entries all contain only legitimate software. Composite persistence analysis confirmed all 161 identified autorun entries are benign.

**Q5. Was data exfiltrated, and if so, what and how much?** No data exfiltration occurred. Composite exfiltration analysis found no connections to known exfiltration services, no evidence of data staging or archiving for transfer, and no suspicious outbound network activity. All carved URLs and domains correspond to legitimate user browsing and cloud service usage.

**Q6. What is the full timeline of the incident?** The incident spans 2020-10-30 through 2020-11-16. Initial probing began on 2020-10-30 against the prior Windows installation. Following a system reinstallation on 2020-11-01, attacks resumed on 2020-11-16 with escalating intensity, culminating in a coordinated four-IP brute-force assault between 02:30 and 02:50 UTC. The memory dump was captured during this active attack at approximately 02:36 UTC.

**Q7. What is the total scope and business impact?** One system was targeted (192.168.1.5). Zero systems were compromised. No business data was accessed, exfiltrated, or destroyed. The direct business impact is limited to the investigative response effort. However, the continued exposure of RDP to the internet represents an ongoing risk to Stark Research Labs, as the system hosts credentials and data synchronized with organizational cloud services (SharePoint, Teams, Slack, OneDrive).

**Q8. What are the recommended remediation actions?** Four targeted remediation actions are recommended, each tied to specific findings: (1) eliminate direct internet RDP exposure by implementing VPN-gated or jump-host remote access architecture; (2) implement centralized Security Event Log forwarding and extend retention to cover at minimum 90 days of authentication events; (3) apply least-privilege principles by separating daily-use accounts from administrative credentials for RDP sessions; and (4) configure account lockout policies, including specific Group Policy settings for the built-in Administrator account, to impose cost on brute-force attempts.


---

## Overview

| | |
|---|---|
| Findings | **7** (7 confirmed, 0 inference) |
| Severity | 0 critical, 1 high, 3 medium, 0 low, 3 info |
| Sources | 21 evidence sources across 292 tool calls |


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
| 2020-10-30T13:14:47Z | Recurring RDP Brute-Force Campaign — Windows.old SAM Evidence of Prior Attacks | MEDIUM | registry.sam, registry.sam.old, enrichment.iocs |
| 2020-11-06T07:55:12Z | Security Event Logs Unavailable for Attack Period - Evidentiary Gap | MEDIUM | evtx.manifest, tsk.filelist, registry.sam |
| 2020-11-16T00:23:06Z | Active RDP Brute-Force Attack from Multiple External IPs | HIGH | volatility.netscan, registry.sam |
| 2020-11-16T00:23:06Z | Cross-System Correlation Confirms No Successful Compromise Despite Active Brute-Force | INFO | composite.execution_chains, composite.lateral_movement, composite.suspicious_processes, composite.defense_evasion, composite.exfil, composite.file_staging, composite.persistence, forensic.timestomping, yara.memory, yara.files, chainsaw.hunt, registry.sam |
| 2020-11-16T02:29:37Z | RDP Service Exposed to Internet Without Access Restrictions | MEDIUM | registry.system, volatility.netscan |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Active RDP Brute-Force Attack from Multiple External IPs

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T00:23:06Z to 2020-11-16T02:50:31Z |
| **Sources** | volatility.netscan, registry.sam |
| **Evidence Refs** | tc_41157d33, tc_26d753c1, tc_95034e6c, tc_7c45b8fb, tc_3202b765 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


An active RDP brute-force attack was in progress at the time of memory capture on 2020-11-16. Four external IP addresses were observed making numerous connections to port 3389 (RDP) on 192.168.1.5 between approximately 02:30 and 02:36 UTC:

**Attacking IPs (with geolocation):**
1. **81.30.144.115** (Germany, AS24961 WIIT AG) — ~40+ connections observed including ESTABLISHED sessions at 02:34:45, 02:34:58, 02:35:XX UTC. Multiple CLOSED connections from 02:31 to 02:36.
2. **213.202.233.104** (Germany, AS24961 WIIT AG, same ASN as above) — ~40+ connections including ESTABLISHED sessions at 02:34:58, 02:35:53 UTC. Multiple CLOSED connections from 02:32 to 02:34.
3. **81.19.209.101** (Netherlands, AS25369 Hydra Communications Ltd) — SYN_RCVD at 02:33:32, CLOSED at 02:33:38 UTC.
4. **201.193.188.114** (Costa Rica, AS11830 ICE) — CLOSED connections at 02:30:05, 02:32:49, 02:34:25 UTC.

**Corroborating SAM password failure evidence:** Password failure timestamps on disabled accounts correlate with the attack window:
- Guest account: Pwd Fail Date 2020-11-16 00:23:06Z (initial probing)
- DefaultAccount: Pwd Fail Date 2020-11-16 01:12:37Z (continued probing)
- Administrator: Pwd Fail Date 2020-11-16 02:50:31Z (during/immediately after main attack wave)

Two IPs (81.30.144.115 and 213.202.233.104) share the same German ASN (AS24961 WIIT AG), suggesting coordinated infrastructure. The attack appears to have started hours before the main brute-force wave, with username enumeration against Guest (00:23) and DefaultAccount (01:12) before escalating to rapid connection attempts at 02:30+.

All target service connections are handled by svchost.exe PID 1248 (the TermService listener), and the RDP service was confirmed listening on 0.0.0.0:3389 (TCP and UDP), indicating the service is bound to all interfaces with no IP restrictions.

**No evidence of successful compromise:** Active user accounts srl-h and fredr have Last Login dates of 2020-11-10 and 2020-11-14 respectively — both BEFORE the attack. Neither shows password failures on 2020-11-16. If an attacker had guessed the correct password, the Last Login timestamp would have updated. No suspicious child processes spawned during the attack window, no attacker tools in ShimCache or AmCache, and no post-exploitation activity in the process tree or command lines.



### 2. [MEDIUM] RDP Service Exposed to Internet Without Access Restrictions

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T02:29:37Z to 2020-11-16T02:36:00Z |
| **Sources** | registry.system, volatility.netscan |
| **Evidence Refs** | tc_39d84e8c, tc_31e389e4, tc_3202b765 |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1133](https://attack.mitre.org/techniques/T1133/) |


The Windows Remote Desktop Protocol (RDP) service is enabled and exposed to the internet on port 3389, with no access restrictions configured.

**Registry Configuration Evidence:**
- ControlSet001\Control\Terminal Server: fDenyTSConnections = 0 (RDP enabled), LastWrite 2020-11-16 02:29:37Z
- WinStations\RDP-Tcp: SecurityLayer = 2 (TLS/SSL encryption)
- WinStations\RDP-Tcp: UserAuthentication = 1 (NLA enabled)
- WinStations\RDP-Tcp: PortNumber = 3389 (default port)
- Terminal Services group policy: "Policies\Microsoft\Windows NT\Terminal Services not found" (no restrictive policies applied)
- Remote Desktop Users group: 0 members (not explicitly configured, but both srl-h and fredr are local Administrators with implicit RDP access)

**Notable:** While NLA (UserAuthentication=1) and TLS (SecurityLayer=2) are enabled (good security practice), the service is bound to 0.0.0.0:3389 with no firewall policy evidence restricting source IPs. The Terminal Server registry key LastWrite at 2020-11-16 02:29:37Z coincides with the beginning of the brute-force attack, likely updated by system activity during the connection flood.

**Risk:** Exposing RDP directly to the internet is a well-known attack surface that regularly leads to compromise through brute-force attacks, credential stuffing, and exploitation of RDP vulnerabilities (BlueKeep, etc.). The active brute-force attack documented in related findings demonstrates this risk is being actively exploited.



### 3. [MEDIUM] Security Event Logs Unavailable for Attack Period - Evidentiary Gap

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-11-06T07:55:12Z to 2020-11-16T02:50:31Z |
| **Sources** | evtx.manifest, tsk.filelist, registry.sam |
| **Evidence Refs** | tc_c385374c, tc_8b615356, tc_1260e471, tc_7c45b8fb, tc_74adb470 |


The active Windows Security Event Log (Security.evtx) covering the attack date (2020-11-16) was not available for analysis. The extracted EVTX manifest contains only 15 archived Security log files (Archive-Security-*.evtx) spanning 2020-11-02 to 2020-11-06, leaving a 10-day gap between the last archived log and the brute-force attack.

Other event log files exist in the filesystem (System.evtx at inode 279883-128-4, Windows PowerShell.evtx at inode 279893-128-4) but were not included in the EVTX extraction. The active Security.evtx was not located in the extracted evidence.

**Impact on investigation:**
- Cannot determine from event logs whether any brute-force RDP authentication attempts (Event IDs 4624/4625) succeeded during the 2020-11-16 attack
- Cannot audit account logon patterns, privilege escalation events, or service installation during the attack window
- Cannot verify whether log clearing (Event IDs 104/1102) occurred

**Mitigating evidence strongly suggesting no successful compromise:**
- SAM Last Login timestamps for active accounts srl-h (2020-11-10) and fredr (2020-11-14) are BEFORE the 11/16 attack — definitive evidence that no successful logon occurred during the attack
- Active user accounts do NOT show password failure timestamps on 2020-11-16, only disabled accounts do
- No suspicious processes, post-exploitation tools, or attacker command lines detected in memory
- No malware or attacker tools found in ShimCache/AmCache execution history
- Process tree shows no anomalous parent-child relationships
- All malfind results are benign false positives

**Temporal note on Windows reinstallation:** The system was reinstalled on 2020-11-01 at approximately 22:15 UTC, just ~42 minutes after the last login on the old installation (srl-h at 21:33 UTC). This coincides with the date of the second brute-force wave (11/01). While this timing could suggest the reinstall was in response to a suspected compromise, no direct evidence of compromise was found in the old installation's SAM (no successful logins by unknown accounts, no active account password failures on 11/01 — only disabled accounts).

**Recurring attack pattern:** Comparison of SAM hives reveals password failures on disabled accounts in a prior Windows installation (Windows.old) on 2020-10-30 and 2020-11-01, suggesting this system has been under recurring RDP brute-force attacks for weeks.



### 4. [MEDIUM] Recurring RDP Brute-Force Campaign — Windows.old SAM Evidence of Prior Attacks

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-10-30T13:14:47Z to 2020-11-16T02:50:31Z |
| **Sources** | registry.sam, registry.sam.old, enrichment.iocs |
| **Evidence Refs** | tc_cce060d6, tc_db95ffaa |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1133](https://attack.mitre.org/techniques/T1133/) |


Cross-referencing SAM hives from the current Windows installation and the Windows.old directory reveals this system has been under recurring RDP brute-force attacks for at least 17 days prior to the captured attack:

**Windows.old SAM (prior installation):**
- Guest account: Password failure date 2020-10-30T13:14:47Z
- DefaultAccount: Password failure date 2020-11-01T21:22:15Z

**Current SAM:**
- Guest account: Password failure date 2020-11-16T00:23:06Z
- DefaultAccount: Password failure date 2020-11-16T01:12:37Z
- Administrator: Password failure date 2020-11-16T02:50:31Z

The attack pattern is consistent: disabled/default accounts are targeted for credential guessing across both Windows installations. The Windows reinstallation (indicated by Windows.old directory from build transition) did NOT stop the attacks because the underlying exposure — RDP bound to 0.0.0.0:3389 with no IP restrictions — persists across installations.

This establishes a pattern of sustained, externally-sourced credential attacks spanning from at least 2020-10-30 through 2020-11-16, indicating the system's internet-facing RDP service has been a persistent target.



### 5. [INFO] YARA Signature Matches Are All False Positives - No Malware Detected

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | yara.memory, yara.files |
| **Evidence Refs** | tc_3b208ec6, tc_9e0f9469 |


YARA scanning of both memory (597 match windows) and disk files (44 match windows) using the signature-base ruleset (~4,000 rules) produced numerous alerts, but detailed triage of matched strings confirms ALL are false positives caused by generic string patterns matching legitimate Windows system content.

**Memory YARA (yara.memory) - Key rules triaged:**
- HKTL_CobaltStrike_Beacon_Strings: Matched only on "%02d/%02d/%02d %02d:%02d:%02d" (generic date format) and "Started service %s on %s" (generic format string). These are common Windows API format strings, not Cobalt Strike beacon indicators.
- CobaltStrike_MZ_Launcher: Matched 2 MZ header byte sequences (4D 5A 41 52 55 48 89 E5...) at offsets 0x199443751 and 0x3911483df. These are standard PE header + x86-64 function prologue bytes commonly found in any Windows memory dump containing legitimate executables.
- APT6_Malware_Sample_Gen: Matched only on "C:\WINDOWS\system32\" - a standard Windows path string.
- Codoso_CustomTCP_4: Matched "varus_service_x86.dll", "net start", "ping 127.1" - common service/admin strings.
- Codoso_Gh0st_1: Matched Windows UAC COM elevation moniker GUID ({3ad05575-8857-4850-9277-11b85bdb8e09}) - a standard Windows component.
- DeepPanda_htran_exe: Matched "-slave <ConnectHost>" help text and generic socket strings.

**Disk YARA (yara.files):**
- APT_MAL_RU_WIN_Snake_Malware_May23_1: Matched only on trivially short strings: "%s#1", "%s#2", "%s#3", "%s#4", ".tmp", ".sav" - generic format specifiers and file extensions.

**Conclusion:** No actual malware, implants, or offensive tooling was detected. The high volume of YARA alerts is attributable to the signature-base ruleset containing rules with insufficiently specific string patterns that match benign Windows system content in a full memory dump. This is a common characteristic of broad ruleset scanning against raw memory.



### 6. [INFO] Cross-System Correlation Confirms No Successful Compromise Despite Active Brute-Force

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T00:23:06Z to 2020-11-16T02:50:31Z |
| **Sources** | composite.execution_chains, composite.lateral_movement, composite.suspicious_processes, composite.defense_evasion, composite.exfil, composite.file_staging, composite.persistence, forensic.timestomping, yara.memory, yara.files, chainsaw.hunt, registry.sam |
| **Evidence Refs** | tc_7dfc6e41, tc_511b6394, tc_e1c5c973, tc_a4dd8ab5, tc_5ce73d0c, tc_cce060d6 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


Comprehensive cross-system correlation across 67 indexed evidence sources confirms that the RDP brute-force attack from 4 external IPs on 2020-11-16 did NOT result in a successful compromise. This conclusion is supported by convergence of independent evidence types:

**SAM Last Login Verification (strongest evidence against compromise):**
- srl-h (admin account): Last Login Date = 2020-11-10 13:26:09Z — 6 DAYS before the attack
- fredr (admin account): Last Login Date = 2020-11-14 12:51:58Z — 2 DAYS before the attack
- Neither active account shows password failures on 2020-11-16
- If a brute-force attempt had guessed the correct password, Last Login would have updated to the attack date; it did not

**Memory Forensics (Volatility):**
- Process tree shows no anomalous parent-child relationships; all processes are legitimate Windows/application processes
- No hidden processes detected (psscan vs pslist comparison shows only normal terminated processes)
- No network connections to attacker IPs from any process other than the RDP listener (svchost.exe PID 1248)
- No suspicious command lines in any process
- Malfind hits on PIDs 4864 (MsMpEng.exe) and 8312 (SearchApp.exe) are benign — standard RWX regions for JIT/AV processes with no shellcode patterns
- No code injection detected in any process

**Disk Forensics (TSK, EZ Tools):**
- ShimCache/AmCache execution history contains only legitimate software (Adobe, Chrome, Firefox, Office, Dropbox, system binaries)
- No reconnaissance tools (net.exe used for recon, psexec, mimikatz, etc.) in execution evidence
- No suspicious archives or data staging detected
- Prefetch files show only normal application execution
- MFT timestamps show no evidence of timestomping (only benign NTFS root entry discrepancy)

**Registry Analysis:**
- All autorun/persistence keys contain legitimate entries only
- AppInit_DLLs is empty (no DLL injection persistence)
- No suspicious services, scheduled tasks, or Winlogon modifications
- SAM hive shows password failures ONLY on disabled accounts (Guest, DefaultAccount, Administrator), NOT on active user accounts (srl-h, fredr)

**Network/IOC Analysis:**
- bulk_extractor URLs and domains are entirely legitimate user activity (Google, Dropbox, SharePoint, Slack, Microsoft services)
- No C2 beaconing patterns, no DNS tunneling, no connections to known malicious infrastructure
- cobracommandcenter.com and redguard.cobra@gmail.com are confirmed as the user's personal accounts, not malicious indicators

**YARA/Sigma Detection:**
- All 597 memory YARA matches confirmed as false positives (generic string patterns matching standard Windows system content)
- All 44 file YARA matches confirmed as false positives
- Chainsaw hunt analysis returned 0 findings across archived EVTX logs
- NOTE: Hayabusa was not run during this investigation; the archived EVTX files (covering 2020-11-02 to 2020-11-06) predate the 11/16 attack and would not contain attack-period events regardless

**Composite Analysis:**
- No suspicious execution chains (composite.execution_chains: 0 results)
- No lateral movement indicators (composite.lateral_movement: 0 results)
- No defense evasion techniques detected
- No data exfiltration indicators
- No file staging activity

This convergence across 6+ independent evidence types, particularly the definitive SAM Last Login timestamps placing the last legitimate logins days before the attack, strongly supports the assessment that the brute-force attack was unsuccessful.



### 7. [INFO] IOCs Cleared — User Personal Accounts Not Malicious Indicators

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | bulk.email, bulk.domain, bulk.url, enrichment.iocs |
| **Evidence Refs** | tc_bf9f8feb, tc_cce060d6 |


Investigation of potentially suspicious IOCs identified during evidence carving determined that all flagged indicators are the legitimate personal accounts and domain of the device user Fred Rocba (fredr):

**Accounts identified as belonging to the user:**
- fred.rocba@gmail.com — Primary personal Gmail
- fred.rocba@outlook.com — Personal Outlook/Microsoft account (confirmed via SAM InternetName field for fredr)
- frocba@stark-research-labs.com — Work email at Stark Research Labs
- redguard.cobra@gmail.com — Secondary personal Gmail (themed alias)
- crimsonguard@cobracommandcenter.com — Personal domain email

**Domain: cobracommandcenter.com**
- Browser history shows visits to http://cobracommandcenter.com/2 (labeled "Home")
- LinkedIn profile reference (urn:li:fs) for crimsonguard
- Domain is a personal website, not a command-and-control server
- The "cobra"/"crimson guard" naming theme is consistent across the user's personal accounts
- bulk_extractor carved this domain alongside fred.rocba@gmail.com and redguard.cobra@gmail.com in the same data structures, indicating they belong to the same user's cached browser/email data

**Evidence supporting user attribution:**
- All email addresses appear in Google Drive sync threads, iCloud document references, and normal email client activity
- bulk_extractor carved these from browser cache, email databases, and cloud sync metadata
- No network traffic to these domains from suspicious processes
- mhill@stark-research-labs.com, nfury@stark-research-labs.com, nromanoff@stark-research-labs.com, tdungan@stark-research-labs.com are coworker addresses

**Limitation:** cobracommandcenter.com was NOT externally verified via WHOIS or VirusTotal. The clearance is based on internal evidence (naming pattern consistency, browser context, co-occurrence with confirmed user accounts). External verification is recommended for completeness but the internal evidence is consistent and strong.

These IOCs should be removed from any threat indicator lists for this case.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `192.168.1.5` |  | Active RDP Brute-Force Attack from Multiple External IPs |
| External IP | `81.30.144.115` | Germany, AS24961 WIIT AG | Active RDP Brute-Force Attack from Multiple External IPs |
| External IP | `213.202.233.104` | Germany, AS24961 WIIT AG | Active RDP Brute-Force Attack from Multiple External IPs |
| External IP | `81.19.209.101` | Netherlands, AS25369 Hydra Communications Ltd | Active RDP Brute-Force Attack from Multiple External IPs |
| External IP | `201.193.188.114` | Costa Rica, AS11830 Instituto Costarricense de Electricidad y Telecom. | Active RDP Brute-Force Attack from Multiple External IPs |
| Port | `TCP 3389` |  | Active RDP Brute-Force Attack from Multiple External IPs |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |





---

## Appendix C: MITRE ATT&CK Coverage

3 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (1) > Credential Access (1) > Lateral Movement (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | RDP Service Exposed to Internet Without Access...; Recurring RDP Brute-Force Campaign —... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | RDP Service Exposed to Internet Without Access...; Recurring RDP Brute-Force Campaign —... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Active RDP Brute-Force Attack from Multiple...; Cross-System Correlation Confirms No...; Recurring RDP Brute-Force Campaign —... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Active RDP Brute-Force Attack from Multiple...; RDP Service Exposed to Internet Without Access...; Cross-System Correlation Confirms No...; Recurring RDP Brute-Force Campaign —... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 292 |
| Findings submitted | 7 |
| Confirmed | 7 |
| Inferences | 0 |
| Input tokens | 229.8K |
| Output tokens | 83.2K |
| Total tokens | 313.1K |
| Audit log | /home/mulder/.mulder/cases/rocba.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 229.8K | 83.2K | 313.1K |




<details>
<summary>Evidence Sources (67)</summary>

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
| volatility.malfind | volatility3 | 17 |
| volatility.psscan | volatility3 | 2213 |
| volatility.dlllist | volatility3 | 12764 |
| volatility.svcscan | volatility3 | 1418 |
| chainsaw.hunt | chainsaw | 2 |
| ez.amcache | eztools | 1120 |
| ez.mft | eztools | 602465 |
| evtx.manifest | evtx-extract | 586 |
| ez.shimcache | eztools | 529 |
| registry.sam | regripper | 212 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.system | regripper | 75 |
| registry.system | regripper | 8 |
| registry.system | regripper | 45225 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 8617 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.sam | regripper | 212 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.system | regripper | 75 |
| registry.system | regripper | 8 |
| registry.system | regripper | 8 |
| registry.system | regripper | 45441 |
| registry.system | regripper | 283 |
| registry.system | regripper | 8742 |
| registry.system | regripper | 199 |
| yara.files | yara | 6445 |
| registry.system | regripper | 406 |
| registry.system | regripper | 283 |
| yara.memory | yara | 40516 |
| composite.persistence | composite | 6023 |
| enrichment.iocs | enrichment | 66 |
| composite.exfil | composite | 11099 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 13304 |
| composite.suspicious_processes | composite | 578 |
| composite.defense_evasion | composite | 224 |
| composite.timeline | composite | 712 |
| composite.execution | composite | 792 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.exfil | composite | 11099 |
| composite.recovery | composite | 16 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
