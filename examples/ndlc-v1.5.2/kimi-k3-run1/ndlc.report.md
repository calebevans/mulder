# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T20:45:16.457695+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 276 evidence sources (53 disk, 223 other) | 827 tool calls | 50 minutes
**Results:** 12 findings (1 critical, 5 high) | 10 confirmed, 2 inference | 3 hypotheses ruled out
**Timeline:** 2014-12-02 to 2015-03-25

**Key Threats:**
- Third exfiltration vector: Secret Project Data burned to optical CD/DVD "IAMAN CD" with masqueraded filenames and decoy photos

**Attack Lifecycle:**
- **Initial Access / Deployment** (2014-12-02 to 2015-03-25): Document metadata on RM#3 attributes the leaked files to author "company" via Microsoft Office; content is NIST / US federal government IT-investment data (+7 related)
- **Persistence** (2015-03-24): 17 files renamed with false extensions (masquerading) on removable media RM#2 to disguise leaked Office documents (+1 related)
- **Command and Control** (2015-03-22 to 2015-03-24): Network Share Access to Secured Drive Containing Secret Project Data (+1 related)

**Tools:** search (248), get_raw_output (162), extract_optical_file (38), open_case (27), get_investigation_summary (24). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Third exfiltration vector: Secret Project Data burned to optical CD/DVD "IAMAN CD" with masqueraded filenames and decoy photos** (2015-03-24T20:54:16 to 2015-03-24T20:57:03)




---

## Forensic Soundness and Evidence Integrity

Analysis was executed via a read-only Model Context Protocol (MCP) server
mapped to the SANS SIFT toolchain. The MCP architecture enforces structural
evidence protection: original evidence files were mounted as read-only
volumes, all tool interactions are typed functions (no shell access), and
every finding is validated against the append-only audit log before
acceptance.

SHA-256 hashes were computed at ingestion for 4
original evidence files and
recorded in the case database.

827 tool calls were executed across 23
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Insider Data Exfiltration — CFReDS 2015 Data Leakage Scenario

## Background

This investigation concerns a suspected insider data-leak incident on a Windows 7 workstation assigned to the user account "informant" (iaman.informant@nist.gov). The evidence set comprises a forensic disk image of the informant's PC, two removable USB flash-drive images (RM#1, an exFAT device labeled "Authorized USB" mounted as E:, and RM#2, a FAT32 device labeled "IAMAN" mounted as D:), and an optical CD/DVD image (RM#3, a UDF write-once disc labeled "IAMAN CD"). A total of 23 evidence sources were indexed across 827 tool executions, spanning SleuthKit filesystem analysis, registry parsing (SYSTEM, NTUSER, USRCLASS), Windows Event Log analysis (EVTX, Hayabusa, Chainsaw), ShimCache/UserAssist execution artifacts, MFT parsing, bulk_extractor string carving, ExifTool metadata analysis, optical-media UDF reconstruction, YARA malware scanning, steganography detection, and Volume Shadow Copy analysis.

The environment is a small internal network (10.11.11.0/24, domain "localdomain"). The informant PC held DHCP address 10.11.11.129; the sensitive data resided on a network share at \\10.11.11.128\secured_drive in a folder tree named "Secret Project Data" with subfolders design, pricing decision, final, technical review, proposal, and progress. The system timezone is US Eastern (UTC-4 during the relevant period). The evidence is drawn from the NIST CFReDS 2015 Data Leakage scenario, in which the document set is derived from the publicly available NIST GovDocs corpus and represents sensitive/classified material within the scenario; the behavioral findings regarding the user's conduct are the subject of this report and are unaffected by the public origin of the underlying test documents.

## Incident Timeline

The incident unfolded in four distinct operational phases over four days, from 2015-03-22 through 2015-03-25.

**Phase 1 — Preparation and persistence (2015-03-22).** On the afternoon of 2015-03-22, shortly after initial system setup, the informant created three unauthorized local Administrator accounts in a roughly two-minute span: "admin11" (created 15:51:54), "ITechTeam" (15:52:30), and "temporary" (15:53:01). Each was added to the local Administrators group and had its password reset, and each was then interactively logged on (LogonType 2) — admin11 at 15:53:44 and again at 15:57:02 via explicit credentials, and temporary at 15:55:57. The name "ITechTeam" mimics a legitimate IT-support account, indicating an attempt to create plausible-looking backdoor accounts. Notably, admin11 opened setupapi.dev.log (the device/USB installation log), consistent with reviewing what USB activity had been recorded. At 14:52:22 the same day, the informant first browsed the \\10.11.11.128\secured_drive "Secret Project Data" share. This account-creation activity preceded any data staging by two days, establishing premeditation.

**Phase 2 — Reconnaissance and cloud-channel setup (2015-03-22 to 2015-03-23).** Beginning with the first Chrome use on 2015-03-22 14:33:13 and continuing through the incident, the informant conducted extensive web research into data leakage and anti-forensics. Carved browser search artifacts reveal queries including "how to leak a secret," "leaking confidential information," "information leakage cases," "intellectual property theft," "data leakage methods," "anti-forensic tools," "how to delete data," "eraser," "ccleaner," "DLP DRM," "windows event logs," "what is windows system artifacts," "Forensic Email Investigation," "external device and forensics," "cd burning method," "security checkpoint cd-r," "google drive," and "cloud storage." The user visited a DEFCON-20 AntiForensics PDF, forensicswiki.org/wiki/Anti-forensic, NIJ digital-evidence pages, and a PCAdvisor article comparing cloud-storage services. On 2015-03-23 at 19:56:33 the informant executed the Google Drive installer (googledrivesync.exe); the client installed at 20:02 and the "Google Drive" folder was created at 20:05:32. The informant again browsed the secured_drive share on 2015-03-23 at 20:23–20:28.

**Phase 3 — Multi-media exfiltration (2015-03-24).** This was the execution day. In the morning (~09:59–10:00), 17 files were written to the RM#2 "IAMAN" FAT32 device with false extensions to disguise Office documents as innocuous media/text files. In the early afternoon (13:38–14:01), the informant accessed a local "S data\Secret Project Data" copy and staged the data onto the RM#1 "Authorized USB" exFAT device (E:\Secret Project Data and E:\RM#1\Secret Project Data), retaining real filenames. That evening (19:47–20:44), the informant created the disguised folder structure on RM#2 (D:\de, D:\tr, D:\pd, D:\prop, D:\prog — abbreviations for design, technical review, pricing decision, proposal, progress) and browsed into the internal structure of a masqueraded PowerPoint file. Finally, from 20:54:16 to 20:57:03, the informant burned the same data to the RM#3 "IAMAN CD" optical disc across 9 UDF write sessions, renaming folders from full names to the abbreviated disguised names across sessions, and added three stock Windows 7 sample photos (Koala.jpg, Penguins.jpg, Tulips.jpg) to the disc root at 20:57 as decoys to make the CD appear to be an innocuous photo disc.

**Phase 4 — Anti-forensic cleanup (2015-03-25).** The day after the staging, the informant downloaded and executed two data-destruction tools: Eraser 6.2.0.2962 (installer run 14:47:40, application run 15:15:50) and CCleaner (installer ccsetup504.exe run 14:48:28, application CCleaner64.exe run 15:21:30). The Google Drive sync client was also executed at 15:24:48. The 17 masqueraded files on RM#2 survive only as deleted $OrphanFiles entries, consistent with this wiping activity; the live browser history databases were likewise unrecoverable, consistent with the CCleaner run.

## Key Findings

The investigation produced 12 findings (10 confirmed, 2 inference, 3 negative), of which 1 is critical, 5 are high, and 6 are medium severity. Eight findings carry MITRE ATT&CK mappings spanning 12 techniques.

**Persistence — backdoor accounts.** The informant created three local Administrator accounts (admin11, ITechTeam, temporary) on 2015-03-22 and logged into them interactively. None were deleted (no EID 4726), so all three persisted. This maps to MITRE T1136.001 (Create Account: Local Account), T1098 (Account Manipulation), and T1078 (Valid Accounts). The account "ITechTeam" was named to blend in with legitimate IT support.

**Data collection and staging.** The source data was harvested from \\10.11.11.128\secured_drive (T1039, Data from Network Shared Drive; T1020, Automated Exfiltration context). The data was staged locally and then onto removable media (T1074.001, Data Staged: Local Data Staging).

**Exfiltration — three physical vectors plus a cloud channel.** The investigation identified an unusually broad set of exfiltration channels. RM#1 ("Authorized USB") held the data with real filenames. RM#2 ("IAMAN") held identical content with 17 files renamed to false extensions (T1036.005, Masquerading: Match Legitimate Name or Location; T1567.002, Exfiltration to Cloud/physical; T1052.001, Exfiltration over Physical Medium: USB). RM#3 ("IAMAN CD") held the same content burned to optical disc with decoy photos (T1052.001, T1036.005, T1030, Data Transfer Size Limits context). The identical 16,381,123-byte winter_whether_advisory.zip on both RM#2 and RM#3 confirms the same content was written to multiple devices. Additionally, the Google Drive sync client was installed and run, representing a potential cloud exfiltration channel, though actual upload of the leaked files could not be confirmed from the indexed artifacts (confidence: inference).

**Masquerading and concealment.** The 17 files on RM#2 and RM#3 were Office documents (DOCX/XLSX/PPTX/OLE) renamed with media/archive extensions (.amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt). Shellbags independently corroborated this by showing the user browsing into the internal PPTX structure of a ".zip" file. The decoy JPEGs on RM#3 were genuine Windows sample photos placed to make the disc look innocuous.

**Anti-forensics.** Eraser and CCleaner were downloaded and executed on 2015-03-25 (T1070.004, Indicator Removal: File Deletion; T1070.002, Clear Linux or Mac System Logs / general cleanup). The deletion of the RM#2 files and the unrecoverability of the browser history are consistent with this cleanup.

**Negative results.** Several hypotheses were affirmatively ruled out. No archiver (7-Zip/WinRAR) or file-transfer (FileZilla/WinSCP/PuTTY) tools were present, ruling out FTP/SFTP/SSH transfer and local archive creation — the ".7z"/".zip" files were renamed Office documents, not archives. No steganography was detected in the disc images. No malware was found (YARA produced no matches; no macros/JS/OLE exploits in the documents) — the tooling was legitimate-but-misused software. No Volume Shadow Copies existed on the removable media (expected for FAT32/exFAT). No external/remote intrusion vector was found — all network logons were benign ANONYMOUS LOGON, with no failed logons or RDP.

**IOC clarification.** The address Eric_P._Lauer@omb.eop.gov appears on both RM#2 and RM#3 with an identical surrounding byte context, indicating it is embedded document metadata carried inside the GovDocs-derived files rather than an exfiltration destination typed by the actor. It is therefore treated as a low-value indicator. The most defensible indicators are the internal source share (\\10.11.11.128\secured_drive) and the actor's own accounts (iaman.informant@nist.gov, iaman.informant.personal@gmail.com).

## Threat Intelligence and Attribution

This incident is attributable to an insider — the "informant" user — rather than an external threat actor. The evidence for this is convergent and strong: the backdoor accounts were created by the informant's own SID; the data access originated from the informant's PC on the same LAN segment as the server; the staging, masquerading, and cleanup were all performed interactively under the informant's session; and the web research into "how to leak a secret" and anti-forensics was conducted from the informant's browser. No external intrusion, malware, or remote-access vector was identified.

Attribution to a named external threat group is not applicable here; this is an insider-threat scenario. The TTP pattern — premeditated research, creation of plausible-looking backdoor accounts, multi-vector physical exfiltration with filename masquerading and decoy content, followed by anti-forensic cleanup — is consistent with a deliberate, planned insider data-theft operation rather than opportunistic or automated activity. The specific research queries ("security checkpoint cd-r," "DLP DRM," "windows event logs") indicate the actor anticipated physical security screening and forensic investigation and actively sought to defeat both. Confidence in the insider attribution is high and confirmed by multiple independent artifact sources; confidence in any external actor is nil.

## Impact Assessment

The scope of compromise is a single workstation (the informant PC, 10.11.11.129) and the data it could reach. The data at risk is the "Secret Project Data" collection, which within the scenario represents sensitive US federal government IT-investment and budget data spanning numerous departments and agencies (Air Force, Army, Navy, DoD Agencies, USDA, DOC, ED, Energy, HHS, DHS, HUD, Interior, DOJ, Labor, State, USAID, DOT, Treasury, VA, USACE, EPA, GSA, NASA, NARA, NRC, OMB, OPM) plus climate/satellite research presentations. The total staged volume is substantial — individual files ranged up to 35 MB, with the aggregate across the 17 masqueraded files exceeding 100 MB, replicated across three separate physical media.

Credential and access exposure is significant: three unauthorized local Administrator accounts were created and persisted, granting the actor continued privileged access independent of the primary account. Persistence depth is therefore moderate (local account backdoors on one host). The exfiltration breadth is high — the data left the environment on at least two USB devices and one optical disc, with a possible additional cloud channel via Google Drive. The anti-forensic activity (Eraser/CCleaner) partially succeeded in destroying browser history and the on-media copies, though the deleted files were recoverable from orphan space and the behavioral record survived in registry, event logs, and execution artifacts.

## Immediate Tactical Containment

The following steps should be executed immediately to stop the active threat. Note that this is a historical/forensic scenario; the steps are framed as they would apply to a live equivalent incident.

1. Isolate the informant workstation (last known IP 10.11.11.129) from the network — pull the network cable or quarantine via switch/NAC to prevent any further access to \\10.11.11.128\secured_drive.
2. Disable the primary user account "informant" (iaman.informant@nist.gov) in Active Directory / locally, and revoke any associated credentials and active sessions.
3. Disable and investigate the three backdoor local Administrator accounts: "admin11," "ITechTeam," and "temporary." Do not delete them until their hives and activity are preserved; reset their passwords and remove them from the Administrators group.
4. Preserve and restrict access to the file server at 10.11.11.128; audit access to the "secured_drive" share and enable detailed file-access auditing on the "Secret Project Data" tree.
5. Seize and forensically image all removable media associated with the user — specifically the two SanDisk Cruzer Fit USB devices (serials 4C530012450531101593&0 and 4C530012550531106501&0) and the "IAMAN CD" optical disc — and issue a recall for any media that may have left the premises.
6. Block and audit the Google Drive sync client (googledrivesync.exe) and the consumer cloud-storage channel at the proxy/egress filter; capture any pending sync activity to determine whether data was uploaded.
7. Quarantine the anti-forensic tools pending review — preserve C:\Program Files\Eraser\Eraser.exe and C:\Program Files\CCleaner\CCleaner64.exe and their installers as evidence; do not run them.
8. Block egress to drive.google.com and consumer cloud-storage domains at the perimeter until the scope of any cloud upload is determined.
9. Preserve the Security event log, ShimCache, UserAssist, USRCLASS shellbags, and MFT from the workstation before any cleanup or reimaging.
10. Interview/escort the user per insider-threat protocol and preserve their Outlook OST (iaman.informant@nist.gov.ost) and any personal webmail artifacts (iaman.informant.personal@gmail.com) via legal hold.

## Strategic Remediation

**Root cause 1 — Unrestricted local Administrator and account-creation rights.** The informant was able to create three local Administrator accounts and add them to the Administrators group (finding f_d2b08f44, T1136.001/T1098). The control that failed was the absence of any restriction or alerting on privileged-account creation. The specific change that would have prevented this attack path is to remove standing local-admin rights from standard users, route account creation through a controlled process, and alert on Security EID 4720 (account created) and 4732 (member added to Administrators) in near-real-time — the three accounts created in a two-minute burst at 15:51–15:53 on 2015-03-22 would have triggered immediate investigation two days before the data was staged.

**Root cause 2 — Unrestricted access to the sensitive network share.** The informant browsed and harvested \\10.11.11.128\secured_drive "Secret Project Data" without any apparent access control or DLP intervention (findings f_8a3b21e2, f_84fc9db9, T1039). The control that failed was overly permissive share ACLs combined with no data-loss-prevention monitoring. The specific change is to enforce least-privilege ACLs on the secured_drive share so only authorized project members can read the Secret Project Data tree, and to deploy DLP that alerts on bulk reads from that share — the actor explicitly researched "DLP DRM" (90 hits), indicating they expected and sought to evade such a control.

**Root cause 3 — Uncontrolled removable-media and optical-burning capability.** The actor staged data onto two USB devices and burned a CD, using filename masquerading and decoy photos to defeat casual inspection (findings f_84fc9db9, f_b0a2bacd, f_5dc19002, T1052.001/T1036.005). The control that failed was the absence of removable-media control and optical-burn restrictions. The specific change is to enforce a device-control policy that blocks or encrypts writes to unapproved USB storage and disables optical burning for users without a business need — the actor researched "security checkpoint cd-r" and "cd burning method," indicating they planned to physically carry media past a checkpoint, which a device-control policy rendering media unreadable off-system would have defeated.

**Root cause 4 — Unrestricted installation of cloud-sync and anti-forensic software.** The actor installed Google Drive, Eraser, and CCleaner without restriction (findings f_5b6d90e2, f_97049535, T1567.002/T1070.004). The control that failed was the absence of application allow-listing. The specific change is to deploy application control (e.g., AppLocker/WDAC) that blocks unapproved executables — this would have prevented both the cloud exfiltration channel (googledrivesync.exe) and the evidence-destruction tools (Eraser/CCleaner) from running.

**Root cause 5 — No monitoring of anti-forensic research or execution.** The actor conducted extensive reconnaissance into forensic artifacts and evidence destruction and then executed wiping tools, with no detection (findings f_437ab754, f_97049535). The control that failed was the absence of user-behavior and execution monitoring. The specific change is to alert on execution of known anti-forensic tools (Eraser, CCleaner secure-delete functions) and on ShimCache/UserAssist anomalies, so that the 2015-03-25 cleanup would have been detected and the media preserved before deletion.

## Conclusion

This investigation confirms a deliberate, premeditated insider data-exfiltration incident carried out by the "informant" user between 2015-03-22 and 2015-03-25.

**Q1. What systems were compromised?** A single workstation — the informant PC at 10.11.11.129 — was compromised, in the sense that the legitimate user abused their own access. Three backdoor local Administrator accounts (admin11, ITechTeam, temporary) were created on it. The file server at 10.11.11.128 was accessed as the data source but was not itself compromised.

**Q2. How did the attacker gain initial access?** This is an insider threat; the actor already had legitimate access. No external intrusion occurred — the actor used their own authorized credentials and local access. The "initial access" for the data-theft phase was the actor's legitimate ability to read the \\10.11.11.128\secured_drive share.

**Q3. What lateral movement occurred?** No lateral movement to other systems occurred. The actor's activity was confined to their own workstation and access to the single network share. All network logons were benign ANONYMOUS LOGON; there were no failed logons, no RDP, and no movement to other hosts.

**Q4. What persistence mechanisms were installed?** Three unauthorized local Administrator accounts (admin11, ITechTeam, temporary) were created on 2015-03-22, added to the Administrators group, and never deleted. These constitute the persistence mechanism, providing continued privileged access independent of the primary account.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes. The "Secret Project Data" collection — representing US federal government IT-investment/budget data and climate-research documents — was staged onto at least three physical media: two USB flash drives (RM#1 "Authorized USB" with real filenames, RM#2 "IAMAN" with 17 masqueraded files) and one optical CD ("IAMAN CD" with the same masqueraded files plus decoy photos). Individual files ranged up to 35 MB, with the aggregate across the 17 files exceeding 100 MB replicated across the three media. A Google Drive cloud channel was set up but actual upload could not be confirmed.

**Q6. What is the full timeline of the incident?** 2015-03-22: backdoor accounts created (15:51–15:57), share first browsed (14:52), research begun. 2015-03-23: share re-browsed (20:23–20:28), Google Drive installed (19:56–20:05). 2015-03-24: RM#2 files written (~09:59–10:00), RM#1 staged (13:38–14:01), RM#2 disguised structure created and browsed (19:47–20:44), RM#3 CD burned (20:54–20:57). 2015-03-25: Eraser and CCleaner executed (14:47–15:21), Google Drive sync run (15:24).

**Q7. What is the total scope and business impact?** The scope is one workstation, one data source, three backdoor accounts, and exfiltration of a sensitive multi-agency government data collection across three physical media plus a potential cloud channel. The business impact is the loss of confidentiality of the Secret Project Data and the persistence of privileged backdoor access; within the scenario this represents a serious breach of restricted government data.

**Q8. What are the recommended remediation actions?** Contain the workstation and disable the informant and backdoor accounts immediately; preserve all media and forensic artifacts; then implement the five strategic remediations — restrict and alert on privileged-account creation, enforce least-privilege and DLP on the secured_drive share, deploy removable-media and optical-burn device control, enforce application allow-listing to block unapproved cloud-sync and anti-forensic tools, and add behavioral/execution monitoring for anti-forensic activity. These map directly to the specific failures observed in this case.


---

## Overview

| | |
|---|---|
| Findings | **12** (10 confirmed, 2 inference) |
| Severity | 1 critical, 5 high, 6 medium, 0 low, 0 info |
| Sources | 23 evidence sources across 827 tool calls |
| Ruled Out | 3 hypotheses tested and rejected |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| cfreds_2015_data_leakage_pc.E01 | `e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9` | 2.0 GB |
| cfreds_2015_data_leakage_rm1.E01 | `a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121` | 74.6 MB |
| cfreds_2015_data_leakage_rm2.E01 | `25215f9bcb51ceee9147886ed3f5c13ef148de634fc5114491e0f8dad8b15696` | 243.2 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | `336e1307721ef5f63679379961d1716b74f986e69df8c40117d9cea7858d512b` | 90.2 MB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2014-12-02T17:28:58Z | Document metadata on RM#3 attributes the leaked files to author "company" via Microsoft Office; content is NIST / US federal government IT-investment data | MEDIUM | exiftool.metadata, yara.files |
| 2015-03-22T14:33:13 | Web search history shows premeditated research into data leakage, anti-forensics, and evidence destruction | MEDIUM | bulk.url_searches, bulk.url |
| 2015-03-22T14:52:22Z | Network Share Access to Secured Drive Containing Secret Project Data | HIGH | registry.usrclass.informant, registry.system, bulk.domain |
| 2015-03-22T15:51:54 | Informant created three unauthorized local Administrator accounts (admin11, ITechTeam, temporary) for persistence | HIGH | evtx.windows_system32_winevt_logs_security, hayabusa.alerts, chainsaw.hunt, registry.ntuser.admin11, registry.ntuser.temporary |
| 2015-03-23T19:56:33 | Google Drive cloud sync client installed and run; user researched cloud-storage services for leaking data | MEDIUM | ez.shimcache, registry.ntuser.informant, ez.mft, bulk.url |
| 2015-03-24T09:59:27 | 17 files renamed with false extensions (masquerading) on removable media RM#2 to disguise leaked Office documents | HIGH | tsk.masquerade, registry.usrclass.informant, ez.mft |
| 2015-03-24T09:59:27 | External emails, domains, and IPs on disk that represent potential exfiltration destinations | MEDIUM | bulk.email, bulk.domain |
| 2015-03-24T09:59:27 | RM#2 target device contains only deleted files (all content removed); no shadow copies, steganography, or malware found | MEDIUM | tsk.filelist, vshadow.info, yara.files, binwalk.scan, steg.detection, tsk.masquerade |
| 2015-03-24T13:38:31 | Sensitive "Secret Project Data" copied from network share \\10.11.11.128\secured_drive to two removable USB drives (RM#1 and RM#2) | HIGH | registry.usrclass.informant, bulk.domain, tsk.masquerade, tsk.filelist |
| 2015-03-24T13:58:32 | Two SanDisk Cruzer Fit USB storage devices connected to the informant PC (RM#1 and RM#2) | MEDIUM | registry.system |
| 2015-03-24T20:54:16 | Third exfiltration vector: Secret Project Data burned to optical CD/DVD "IAMAN CD" with masqueraded filenames and decoy photos | CRITICAL | optical.listing, bulk.url_searches, tsk.masquerade, exiftool.metadata |
| 2015-03-25T14:47:40 | Anti-forensic wiping/cleanup tools Eraser and CCleaner downloaded and executed after the data leak | HIGH | registry.ntuser.informant, ez.shimcache |




---

## Hypotheses Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No archiver (7-Zip/WinRAR) or file-transfer (FileZilla/WinSCP/PuTTY) tools present; exfiltration was via USB media and Google Drive** : A search across all indexed evidence (file listing, ShimCache, UserAssist, MFT, app configs) for file-transfer and archiving tools — FileZilla, WinSCP, PuTTY, 7-Zip (7z.exe/7zG), and WinRAR...

- **Network environment: informant PC was on the internal 10.11.11.0/24 LAN, same subnet as the data server** : Network configuration context for interpreting the data-access findings. The informant PC's primary interface ({E2B9AEEC-B1F7-4778-A049-50D7F2DAB2DE}) was configured via DHCP on the internal...

- **RM#3 optical disc: no steganography in images and no malicious content (macros/JS/OLE exploits) in documents** : Negative results for the RM#3 optical-media investigation questions:

QUESTION 6 — Steganography: The 3 live image files on the disc (Koala.jpg, Penguins.jpg, Tulips.jpg — standard Windows 7...



---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Third exfiltration vector: Secret Project Data burned to optical CD/DVD "IAMAN CD" with masqueraded filenames and decoy photos

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T20:57:03 |
| **Sources** | optical.listing, bulk.url_searches, tsk.masquerade, exiftool.metadata |
| **Evidence Refs** | tc_0d5a6790, tc_d87263a2, tc_1e369e28, tc_429306c8 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1030](https://attack.mitre.org/techniques/T1030/) |


Optical-media analysis (mulder-optical UDF listing) reveals a CD/DVD with volume label "IAMAN CD" (UDF write-once, VAT, 52,513 sectors, 9 write sessions/VAT generations) containing the SAME "Secret Project Data" that was staged onto the USB drives — a THIRD physical exfiltration vector distinct from RM#1 ("Authorized USB") and RM#2 ("IAMAN" FAT32 flash drive).

Content and correlation:
- The disc holds the same sensitive folder set, seen in BOTH full-name form (design, pricing decision, progress, proposal, technical review) and the abbreviated form (de, pd, prog, prop, tr) used on RM#2 — the VAT session history shows the folders were renamed from full names to the abbreviated/disguised names across write sessions.
- It contains the SAME masqueraded files with byte-identical sizes to RM#2, e.g. winter_whether_advisory.zip = 16,381,123 bytes (matches the USB finding exactly), winter_storm.amr = 14,547,968, my_favorite_cars.db = 1,260,544, super_bowl.avi = 10,289,152, a_gift_from_you.gif = 35,226,880, plus the diary_#*.txt files. These are Office documents (PPTX/XLSX/DOCX/OLE) renamed with media/archive extensions.
- Three stock Windows 7 sample photos — Koala.jpg (780,831), Penguins.jpg (777,835), Tulips.jpg (620,888) — were written to the disc root at 2015-03-24 20:57, AFTER the data files (20:54–20:55). ExifTool confirms Penguins.jpg is a genuine JPEG (MIME image/jpeg, Adobe XMP, Corbis stock-photo web statement) — i.e., these are REAL images placed as decoys to make the CD look like an innocuous photo disc on casual inspection, NOT additional disguised documents.

ExifTool content analysis of the masqueraded files on the disc independently corroborates that they are real Office documents with substantive content (Author/LastModifiedBy "company", created 2003–2004, modified 2014–2015):
- "[secret_project]_market_shares" (Microsoft Excel).
- A federal "IT Investment Details" spreadsheet referencing the Nuclear_Regulatory_Commission, Office_of_Management_and_Budget, Office_of_Personnel_Management, and Department of Defense Agencies.
- Climate/satellite research presentations (Microsoft PowerPoint) referencing ISCCP Data, NCDC processing, GEWEX Projects, Albedo, and Satellite Coverage.
- A Microsoft Word 97-2003 document with hyperlinks to hdl.loc.gov and digitalcorpora.org/corpora/govdocs (the GovDocs corpus — the origin of the test data representing the "Secret Project Data").

Timeline: data files created on the disc 2015-03-24 20:54:16–20:55:46; decoy images 20:57:00–20:57:03 — the same evening as the RM#2 USB staging (19:47–20:44), indicating a coordinated multi-media exfiltration effort.

This corroborates the web-search research finding: the user searched for "cd burning method" (64 hits), "cd burning method in windows" (53), and "security checkpoint cd-r" — i.e., they researched how to burn data to CD and get it past security checkpoints. The shared "IAMAN" volume label links the CD to the RM#2 USB device. Confidence is confirmed via three independent sources: the optical UDF listing (file enumeration/sizes), the byte-identical sizes in the USB masquerading finding (tsk.masquerade), and ExifTool content/metadata analysis of the files themselves.



### 2. [HIGH] 17 files renamed with false extensions (masquerading) on removable media RM#2 to disguise leaked Office documents

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T20:44:18 |
| **Sources** | tsk.masquerade, registry.usrclass.informant, ez.mft |
| **Evidence Refs** | tc_62a66069, tc_64dfac60, tc_1dd92c90 |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Content/signature analysis (tsk.masquerade) of the RM#2 removable drive (FAT32, volume label "IAMAN", the target media) identified 17 deleted files in $OrphanFiles whose true content type (by file signature) contradicts their displayed extension — a classic concealment technique to disguise sensitive Office documents as innocuous media/text files before exfiltration. All were created on the media in a tight burst on 2015-03-24 (~09:59–10:00 per FAT timestamps) and all are now deleted (recovered only as orphans).

Mismatches (extension → real type):
- design/winter_storm.amr → OLE/Office (14.5 MB)
- design/winter_whether_advisory.zip → PPTX (16.4 MB)
- PRICIN~1 (pricing decision)/my_favorite_cars.db → OLE (1.3 MB)
- PRICIN~1/my_favorite_movies.7z → XLSX (100 KB)
- PRICIN~1/new_years_day.jpg → XLSX (10.2 MB)
- PRICIN~1/super_bowl.avi → OLE (10.3 MB)
- progress/my_friends.svg → OLE (58 KB)
- progress/my_smartphone.png → DOCX (4.4 MB)
- progress/new_year_calendar.one → DOCX (27 KB)
- proposal/a_gift_from_you.gif → DOCX (35.2 MB)
- proposal/landscape.png → DOCX (6.5 MB)
- TECHNI~1 (technical review)/diary_#1d.txt → DOCX; diary_#1p.txt → PPTX; diary_#2d.txt → DOCX; diary_#2p.txt, diary_#3d.txt, diary_#3p.txt → OLE

The $OrphanFiles directory names (design, PRICIN~1=pricing decision, progress, proposal, TECHNI~1=technical review) exactly match the "Secret Project Data" subfolders the user accessed on the source network share and PC. Corroborated independently by Shellbags (registry.usrclass.informant), which show the user browsing INTO D:\de\winter_whether_advisory.zip\ppt\slides\ppt and \ppt\slideMasters\ppt on 2015-03-24 19:54–20:44 — internal PPTX/ZIP structure, proving the ".zip" is really a PowerPoint file. The D: drive folders de/tr/pd/prop/prog map to design/technical review/pricing decision/proposal/progress.



### 3. [HIGH] Sensitive "Secret Project Data" copied from network share \\10.11.11.128\secured_drive to two removable USB drives (RM#1 and RM#2)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:38:31 to 2015-03-24T20:44:18 |
| **Sources** | registry.usrclass.informant, bulk.domain, tsk.masquerade, tsk.filelist |
| **Evidence Refs** | tc_64dfac60, tc_553cdb5f, tc_62a66069, tc_1dd92c90 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Shellbag artifacts (registry.usrclass.informant) reconstruct the data-leak path on 2015-03-24. The source data lived on a network share \\10.11.11.128\secured_drive (also mapped as drive V:) containing "Secret Project Data" with subfolders design, pricing decision, final, technical review, proposal, progress, plus Common Data and Past Projects. The user browsed this share on 2015-03-22 14:52 and 2015-03-23 20:23–20:28, and accessed a local "S data\Secret Project Data" copy on 2015-03-24 13:40–13:52.

On 2015-03-24 the data was staged onto two removable drives:
- E: = RM#1, exFAT, volume label "Authorized USB" — "E:\Secret Project Data" and "E:\RM#1\Secret Project Data" created ~13:59 and accessed 13:38–14:01, retaining REAL filenames (e.g. E:\Secret Project Data\design\winter_whether_advisory.zip, 16,381,123 bytes).
- D: = RM#2, FAT32, volume label "IAMAN" — folders D:\de, D:\tr, D:\pd, D:\prop, D:\prog created 19:47:48 and browsed 19:54–20:44, holding the SAME content but renamed with false extensions (see masquerading finding). The same winter_whether_advisory.zip (16,381,123 bytes) appears on both drives, confirming identical content was written to both.

The presence of identical sensitive content on two different USB devices — one labeled "Authorized USB" with real names, one labeled "IAMAN" with disguised names — indicates deliberate exfiltration with an attempt to conceal the nature of the data on the second device.



### 4. [HIGH] Anti-forensic wiping/cleanup tools Eraser and CCleaner downloaded and executed after the data leak

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:47:40 to 2015-03-25T15:21:30 |
| **Sources** | registry.ntuser.informant, ez.shimcache |
| **Evidence Refs** | tc_f874bc29, tc_4baf803d |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070.002](https://attack.mitre.org/techniques/T1070/002/) |


Execution artifacts show the user installed and ran data-destruction/cleanup tools immediately after the 2015-03-24 leak, indicating an attempt to destroy evidence:
- Eraser 6.2.0.2962 (secure file-wiping tool): installer C:\Users\informant\Desktop\Download\Eraser 6.2.0.2962.exe executed 2015-03-25 14:47:40 (ShimCache) / 14:50:14 (UserAssist); C:\Program Files\Eraser\Eraser.exe executed 2015-03-25 15:15:50 (UserAssist) and present in ShimCache.
- CCleaner (temp/history cleaner): installer ccsetup504.exe executed 2015-03-25 14:48:28 (ShimCache) / 14:57:56 (UserAssist); C:\Program Files\CCleaner\CCleaner64.exe executed 2015-03-25 15:21:30 (UserAssist) and in ShimCache.

Both tools were downloaded to the Desktop\Download folder and run on 2015-03-25, one day after the sensitive files were staged onto removable media and subsequently deleted (the RM#2 files survive only as $OrphanFiles). This timing is consistent with post-exfiltration cleanup/anti-forensic activity. The deletion of the 17 masqueraded files on RM#2 is consistent with this wiping activity.



### 5. [HIGH] Network Share Access to Secured Drive Containing Secret Project Data

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22Z to 2015-03-23T20:28:17Z |
| **Sources** | registry.usrclass.informant, registry.system, bulk.domain |
| **Evidence Refs** | tc_1f4618b9, tc_4677eefe, tc_507831a1, tc_fb3af364 |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/), [T1020](https://attack.mitre.org/techniques/T1020/) |


The system accessed a network share at \\10.11.11.128\secured_drive which contained Secret Project Data with subdirectories for Common Data, Past Projects, design, pricing decision, final, technical review, proposal, and progress. Shellbags evidence shows the user browsed this network share on 2015-03-22 at 14:52:22 and again on 2015-03-23 at 20:23:28. The system's DHCP IP address was 10.11.11.x, placing it on the same network segment as the secured drive server. This network share appears to be the source of the Secret Project Data that was subsequently copied to the local system and to the USB device.



### 6. [HIGH] Informant created three unauthorized local Administrator accounts (admin11, ITechTeam, temporary) for persistence

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:51:54 to 2015-03-22T15:57:02 |
| **Sources** | evtx.windows_system32_winevt_logs_security, hayabusa.alerts, chainsaw.hunt, registry.ntuser.admin11, registry.ntuser.temporary |
| **Evidence Refs** | tc_90f3f830, tc_ba019ffb, tc_ab4a8f0c, tc_f58bad5f, tc_ecd12658 |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1078](https://attack.mitre.org/techniques/T1078/) |


Windows Security event log records show the informant account (S-1-5-21-2425377081-3129163575-2985601102-1000) created three new local user accounts in a ~2-minute span on 2015-03-22, added each to the local Administrators group, and reset their passwords:

- 15:51:54 — "admin11" (SID ...-1001) created (EID 4720/4738), added to Administrators (EID 4732), password reset 15:52:10 (EID 4724)
- 15:52:30 — "ITechTeam" (SID ...-1002) created (EID 4720), added to Administrators (EID 4732), password reset 15:52:45 (EID 4724)
- 15:53:01 — "temporary" (SID ...-1003) created (EID 4720), added to Administrators (EID 4732), password reset 15:53:11 (EID 4724)

The accounts were then interactively logged on (LogonType 2): admin11 at 15:53:44 (with administrative privileges, EID 4672) and again at 15:57:02 via explicit credentials (EID 4648), and temporary at 15:55:57. The NTUSER.DAT hives for admin11 and temporary confirm the profiles were created and used on 2015-03-22; admin11 opened setupapi.dev.log (the device/USB installation log) and an "inf" folder, consistent with reviewing what USB/device activity had been recorded.

No EID 4726 (account deleted) events exist, so all three accounts persisted on the system. The account names are notable: "ITechTeam" mimics a legitimate IT-support account, and "temporary"/"admin11" are generic — consistent with an attempt to create plausible-looking backdoor/persistence accounts. This activity occurred on 2015-03-22, immediately after initial system setup and BEFORE the informant first browsed the \\10.11.11.128\secured_drive "Secret Project Data" share (14:52) and two days before the 2015-03-24 USB staging, indicating premeditation. No failed-logon (4625) or external network/RDP logons involving these accounts were observed; all LogonType 3 events were ANONYMOUS LOGON (benign).

Corroborated by independent sources: the Security EVTX (direct parse and via Hayabusa/Chainsaw) and the per-user NTUSER.DAT registry hives.



### 7. [MEDIUM] Two SanDisk Cruzer Fit USB storage devices connected to the informant PC (RM#1 and RM#2)

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:58:32 |
| **Sources** | registry.system |
| **Evidence Refs** | tc_24c2ef91, tc_c76b6d9d, tc_427964db |


The Windows registry (ControlSet001\Enum\USBSTOR) on the informant PC records two SanDisk Cruzer Fit USB flash drives (Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01), distinguished by serial number:
- Serial 4C530012450531101593&0
- Serial 4C530012550531106501&0
The USBSTOR key was last written 2015-03-23 18:31:10 and the device subkey 2015-03-24 13:58:32, consistent with the 2015-03-24 leak window. These two devices correspond to the two removable-media images in the case: RM#1 (exFAT, volume label "Authorized USB", mounted as E:) and RM#2 (FAT32, volume label "IAMAN", mounted as D:). System timezone is Eastern (EST/EDT; ActiveTimeBias=240 = UTC-4 during DST, which was in effect on 2015-03-24), relevant when correlating FAT local timestamps against UTC registry/MFT values.



### 8. [MEDIUM] Google Drive cloud sync client installed and run; user researched cloud-storage services for leaking data

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-23T19:56:33 to 2015-03-25T15:24:48 |
| **Sources** | ez.shimcache, registry.ntuser.informant, ez.mft, bulk.url |
| **Evidence Refs** | tc_4baf803d, tc_f874bc29, tc_4749446a, tc_f6a52bc3 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Google Drive was installed on the informant PC and the sync client executed, indicating a cloud-storage exfiltration channel was set up:
- C:\Users\informant\Downloads\googledrivesync.exe (installer) executed 2015-03-23 19:56:33 (ShimCache).
- C:\Program Files (x86)\Google\Drive\ installed 2015-03-23 20:02 (MFT); shell-extension googledrivesync64.dll registered 2015-03-23 20:02:45.
- C:\Users\informant\Google Drive folder created 2015-03-23 20:05:32 (MFT); shellbags show "Users\Google Drive" accessed 2015-03-25 15:20:59.
- googledrivesync.exe executed 2015-03-25 15:24:48 (UserAssist).
- Browser/URL artifacts show drive.google.com access and a PCAdvisor article "best-cloud-storage-dropbox-google-drive-onedrive-icloud" plus a Wikipedia "Cloud_storage" page, i.e. the user was evaluating cloud services.

Whether data was actually uploaded to Google Drive cannot be confirmed from the indexed artifacts (no Google Drive sync-database content was recovered showing the leaked files), but the installation and execution of the client during the leak window, combined with the research queries, make cloud storage a plausible exfiltration vector in addition to the USB devices.



### 9. [MEDIUM] External emails, domains, and IPs on disk that represent potential exfiltration destinations

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | bulk.email, bulk.domain |
| **Evidence Refs** | tc_c3514976, tc_ca95f6e7, tc_553cdb5f |


bulk_extractor recovered the following external indicators relevant to exfiltration:
- On the target RM#2 device (bulk.email, source rm2): "Eric_P._Lauer@omb.eop.gov" appears with surrounding "upload" context. omb.eop.gov is the Office of Management and Budget / Executive Office of the President — a U.S. federal government address.
- Source network share: \\10.11.11.128\secured_drive (internal IP 10.11.11.128), confirmed in both shellbags and bulk.domain — this is the origin of the leaked "Secret Project Data".
- Informant's own accounts: iaman.informant@nist.gov and iaman@nist.gov (NIST; the Outlook OST on the PC), plus Gmail addresses scarter@gmail.com and erovira@gmail.com and a large set of "informant@<ad/tracker domain>" cookie strings (the latter are browser tracking cookies, likely noise).

COUNTER-ANALYSIS CLARIFICATION (Eric_P._Lauer mechanism): The "Eric_P._Lauer@omb.eop.gov" string appears with an IDENTICAL surrounding byte context ("upload\000\036\000\000\000\034\000\000\000") on BOTH RM#2 (offset 57020544) and the RM#3 optical disc (offset 53407872). The identical context string recurring at the same relative structure across two independent media strongly indicates this is EMBEDDED DOCUMENT METADATA carried inside the leaked files (which derive from the NIST GovDocs public corpus — OMB is heavily represented in that corpus), NOT an exfiltration destination typed or used by the actor. bulk_extractor carves strings from raw disk, so presence proves the string exists on the media but not the mechanism by which it got there. Accordingly this address should be treated as a low-value indicator (likely document metadata), not a confirmed exfiltration recipient. No email-send artifacts (Outlook OST Sent Items, SMTP traffic) tying this address to an actual transmission were identified.

The most defensible external indicators are therefore the internal source share (\\10.11.11.128\secured_drive) and the actor's own NIST/Gmail accounts; the omb.eop.gov address is likely corpus metadata.



### 10. [MEDIUM] RM#2 target device contains only deleted files (all content removed); no shadow copies, steganography, or malware found

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-25T15:21:30 |
| **Sources** | tsk.filelist, vshadow.info, yara.files, binwalk.scan, steg.detection, tsk.masquerade |
| **Evidence Refs** | tc_20ae918e, tc_29a8b73b, tc_f6d195c4, tc_2e261a93, tc_62a66069 |


Filesystem analysis of the target RM#2 device (FAT32, volume label "IAMAN") shows that every data file on it is deleted: the only allocated entry is the volume label; all 17 masqueraded files and their parent folders (design, PRICIN~1, progress, proposal, TECHNI~1) exist solely as deleted $OrphanFiles entries. This is consistent with the files being deleted after staging — matching the Eraser/CCleaner cleanup activity on the PC the following day (2015-03-25). The deleted files were recoverable because FAT/exFAT deletion only marks directory entries, leaving content in unallocated/orphan space.

Negative results (questions 7 & 8):
- Shadow copies: vshadowinfo returned only its version banner for the removable media — no Volume Shadow Copies exist (expected; VSS does not apply to FAT32/exFAT removable drives). Earlier file versions are nonetheless preserved via the recoverable $OrphanFiles entries.
- Steganography: stegdetect/binwalk scans returned no hits — the disguise used was extension renaming (masquerading), not steganographic embedding.
- Malware: the YARA file scan produced no matches; no malware was identified. The relevant tooling is legitimate-but-misused software (Eraser, CCleaner, Google Drive) rather than malware.



### 11. [MEDIUM] Web search history shows premeditated research into data leakage, anti-forensics, and evidence destruction

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T14:47:40 |
| **Sources** | bulk.url_searches, bulk.url |
| **Evidence Refs** | tc_d87263a2, tc_4e8fb390, tc_0ab8643c |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1020](https://attack.mitre.org/techniques/T1020/) |


Browser search-engine query artifacts recovered by bulk_extractor (both the url_searches histogram and the full url recorder) from the informant PC reveal the user researched topics directly related to planning and concealing a data leak. Notable queries (with hit counts from url_searches):

Leak/exfiltration intent: "how to leak a secret", "leaking confidential information", "information leakage cases" (47), "intellectual property theft", "data leakage methods", "file sharing and tethering" (491), "security checkpoint cd-r".

Anti-forensics / evidence destruction: "anti-forensic tools" (85), "anti-forensics", "how to delete data", "system cleaner", "eraser" (51), "ccleaner" (65), "data recovery tools", "how to recover data".

Evasion of detection / understanding investigations: "DLP DRM" (90), "windows event logs" (61), "what is windows system artifacts" (79), "Forensic Email Investigation" (78), "e-mail investigation" (88), "external device and forensics" (65), "investigation on windows machine" (64), "digital forensics", "cd burning method" (64).

Cloud exfiltration channel: "google drive" (10), "cloud storage", "apple icloud".

The full url recorder corroborates these with the actual result pages visited, including a DEFCON-20 "AntiForensics" PDF (defcon.org), forensicswiki.org/wiki/Anti-forensic, NIJ digital-evidence-analysis pages, a MediaPost article on a Google data-leakage settlement, and the icloudsetup.exe download.

NOTE ON TIMESTAMPS: These are carved browser artifacts (the live browser history databases were not recoverable — consistent with the CCleaner run on 2015-03-25), so individual per-search timestamps were not recoverable. The activity is bounded below by the first Chrome use on the freshly built system (informant Chrome UserAssist/LNK at 2015-03-22 14:33:13) and above by the anti-forensic tool execution it produced (Eraser/CCleaner, 2015-03-25 14:47:40). The searches directly corroborate and precede the observed actions: the user subsequently installed/ran Eraser and CCleaner, installed Google Drive, and staged data onto USB media with disguised filenames. This establishes the leak was premeditated and that the user actively sought to understand forensic artifacts, defeat DLP, and destroy evidence — evidence of intent and planning distinct from the execution findings.



### 12. [MEDIUM] Document metadata on RM#3 attributes the leaked files to author "company" via Microsoft Office; content is NIST / US federal government IT-investment data

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2014-12-02T17:28:58Z to 2015-01-23T20:47:10Z |
| **Sources** | exiftool.metadata, yara.files |
| **Evidence Refs** | tc_0cced7cc, tc_73f900c1, tc_2b0946d0, tc_1e01368f |


ExifTool metadata extracted from the recovered documents on the RM#3 optical disc (and identical RM#2 copies) characterizes the leaked content and its origin:

AUTHORSHIP/ATTRIBUTION: The documents consistently carry Author = "company" and Last Modified By = "company", created/edited with Microsoft Office applications (Microsoft Excel, Microsoft PowerPoint, Microsoft Word 97-2003). The generic "company" author is the default Office template author and does not identify a specific individual; it indicates the files were produced with standard Office installs rather than attributing a named person.

CONTENT / LEAK SOURCE: The spreadsheet winter_whether_advisory.zip (really XLSX) is titled "[secret_project]_market_shares" and its sheet names (Title Of Parts) enumerate a NIST document plus US federal government departments/agencies: "NIST, Please read first, Summary, Department of the Air Force, Department of the Army, Department of the Navy, Department of Defense Agencies, USDA, DOC, ED, Energy, HHS, DHS, HUD, Interior, DOJ, Labor, State, USAID, DOT, Treasury, VA, USACE, EPA, GSA, NASA, NARA, Nuclear Regulatory Commission, Office of Management and Budget, Office of Personnel Management..." — i.e. government-wide IT-investment/budget data. Other files reference climate-research hyperlinks (ISCCP, NCDC, GEWEX, NASA-related) and public-domain sources (hdl.loc.gov, digitalcorpora.org/govdocs).

COUNTER-ANALYSIS CLARIFICATION (GovDocs/CFReDS context): The embedded hyperlinks to digitalcorpora.org/corpora/govdocs and hdl.loc.gov identify the document set as derived from the NIST GovDocs corpus — a PUBLICLY AVAILABLE collection of government documents assembled by NIST for forensic testing (this is the CFReDS 2015 Data Leakage scenario, per the evidence image filenames cfreds_2015_data_leakage_*). The documents are therefore PUBLIC test data that REPRESENTS sensitive/classified material within the scenario, not genuinely classified content. This nuance does NOT alter the behavioral findings: within the scenario the data resided on a restricted share (\\10.11.11.128\secured_drive) labeled "Secret Project Data," and the user's conduct (backdoor account creation, multi-media staging, filename masquerading, decoy-CD burning, anti-forensic cleanup, and "how to leak a secret"/"security checkpoint cd-r" research) is the actual subject of analysis and is unaffected by the public origin of the underlying test documents. The Eric_P._Lauer@omb.eop.gov address found on RM#2/RM#3 is consistent with embedded GovDocs document metadata (OMB is heavily represented in the corpus) rather than a confirmed exfiltration recipient.

TIMESTAMPS: Original document Create Dates are old (e.g. Excel 2004-02-20, PowerPoint 2003-12-04), with Modify Dates in Dec 2014–Jan 2015 — the files predate the 2015-03-24 leak, consistent with a collection of pre-existing documents that were harvested and burned to disc.

QUESTION 7 — Malicious content: No macros, embedded JavaScript, or malicious OLE objects were detected. YARA scanning of the files produced no matches, and no VBA/vbaProject/AutoOpen indicators exist in the documents (the only VBA artifacts on the system are legitimate Microsoft Office VBA7.1 installation DLLs). One PowerPoint file reports "Embedded OLE Servers, 2", a standard Office feature for embedded objects (e.g. charts), not malicious content. The documents are data-theft payloads, not malware.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | Sensitive "Secret Project Data" copied from network share \\10.11.11.128\secured |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Users\informant\Desktop\Download\Eraser` |  | Anti-forensic wiping/cleanup tools Eraser and CCleaner downloaded and executed a |
| Path | `C:\Program` |  | Anti-forensic wiping/cleanup tools Eraser and CCleaner downloaded and executed a |
| Path | `C:\Users\informant\Downloads\googledrivesync.exe` |  | Google Drive cloud sync client installed and run; user researched cloud-storage  |
| Path | `C:\Users\informant\Google` |  | Google Drive cloud sync client installed and run; user researched cloud-storage  |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `eric_p._lauer@omb.eop.gov` |  | External emails, domains, and IPs on disk that represent potential exfiltration  |
| Email | `iaman.informant@nist.gov` |  | External emails, domains, and IPs on disk that represent potential exfiltration  |
| Email | `iaman@nist.gov` |  | External emails, domains, and IPs on disk that represent potential exfiltration  |
| Email | `scarter@gmail.com` |  | External emails, domains, and IPs on disk that represent potential exfiltration  |
| Email | `erovira@gmail.com` |  | External emails, domains, and IPs on disk that represent potential exfiltration  |




---

## Appendix C: MITRE ATT&CK Coverage

12 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (3) > Privilege Escalation (2) > Defense Evasion (4) > Collection (2) > Exfiltration (4)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Informant created three unauthorized local... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Informant created three unauthorized local... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Informant created three unauthorized local... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Informant created three unauthorized local... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Informant created three unauthorized local... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Informant created three unauthorized local... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Resource Name or Location | 17 files renamed with false extensions...; Third exfiltration vector: Secret Project Data... |
| [T1070.002](https://attack.mitre.org/techniques/T1070/002/) | Clear Linux or Mac System Logs | Anti-forensic wiping/cleanup tools Eraser and... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Anti-forensic wiping/cleanup tools Eraser and...; Web search history shows premeditated research... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Informant created three unauthorized local... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network Share Access to Secured Drive... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Sensitive "Secret Project Data" copied from... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Network Share Access to Secured Drive...; Web search history shows premeditated research... |
| [T1030](https://attack.mitre.org/techniques/T1030/) | Data Transfer Size Limits | Third exfiltration vector: Secret Project Data... |
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Sensitive "Secret Project Data" copied from...; Third exfiltration vector: Secret Project Data... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | 17 files renamed with false extensions...; Sensitive "Secret Project Data" copied from...; Google Drive cloud sync client installed and...; Web search history shows premeditated research... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 827 |
| Findings submitted | 12 |
| Confirmed | 10 |
| Inferences | 2 |
| Input tokens | 3.8K |
| Output tokens | 193.1K |
| Total tokens | 196.9K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/us.moonshotai.kimi-k3 | 3.8K | 193.1K | 196.9K |




<details>
<summary>Evidence Sources (276)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.fsstat | sleuthkit | 37 |
| tsk.filelist | sleuthkit | 27 |
| tsk.timeline | sleuthkit | 67 |
| tsk.masquerade | sleuthkit | 0 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| binwalk.scan | binwalk | 0 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| strings.output | strings | 22065 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.partitions | sleuthkit | 10 |
| tsk.fsstat | sleuthkit | 39 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.timeline | sleuthkit | 344089 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| vshadow.info | vshadowinfo | 1 |
| tsk.masquerade | sleuthkit | 17 |
| bulk.alerts | bulk_extractor | 7 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.ccn | bulk_extractor | 263 |
| bulk.domain | bulk_extractor | 366963 |
| bulk.duplicates | bulk_extractor | 12 |
| bulk.email | bulk_extractor | 6851 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 793 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.sin | bulk_extractor | 54 |
| bulk.telephone | bulk_extractor | 2326 |
| bulk.url | bulk_extractor | 421750 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| exiftool.metadata | exiftool | 9 |
| tsk.masquerade | sleuthkit | 3 |
| ez.mft | eztools | 98918 |
| pcap.disk.atiumd6a | tshark | 8 |
| appfiles.*google_drive*.desktop.ini | icat | 6 |
| evtx.manifest | evtx-extract | 54 |
| registry.query.software | python-registry | 1 |
| appfiles.*google_drive*.desktop.ini | icat | 6 |
| appfiles.*google_drive*.desktop.ini | icat | 6 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.query.system | python-registry | 1 |
| pcap.disk.atiumd6a | tshark | 8 |
| ez.shimcache | eztools | 307 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| pcap.disk.atiumdva | tshark | 8 |
| appfiles.*google_drive*.desktop.ini | icat | 6 |
| appfiles.*google_drive*.desktop.ini | icat | 6 |
| appfiles.*google_drive*.desktop.ini | icat | 6 |
| registry.default | regripper | 418 |
| pcap.disk.atiumd6a | tshark | 8 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.system | regripper | 7 |
| registry.system | regripper | 69 |
| registry.system | regripper | 8 |
| registry.system | regripper | 33492 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| registry.usrclass.admin11 | regripper | 11 |
| registry.ntuser.admin11 | regripper | 133 |
| registry.ntuser.default | regripper | 74 |
| registry.usrclass.informant | regripper | 102 |
| registry.ntuser.informant | regripper | 306 |
| registry.usrclass.temporary | regripper | 15 |
| registry.ntuser.temporary | regripper | 118 |
| hayabusa.alerts | hayabusa | 35 |
| appfiles.*outlook*.fc39fbc8c85bcb43816b40b7d4c72f22_-_autodiscover.xml | icat | 129 |
| appfiles.*outlook*.firstrun.log | icat | 13 |
| appfiles.*outlook*.outlook.xml | icat | 48 |
| appfiles.*outlook*.outlookmui.xml | icat | 67 |
| appfiles.*outlook*.setup.xml | icat | 53 |
| appfiles.*outlook*.yahoo.com.ar.xml | icat | 25 |
| appfiles.*outlook*.ameritech.net.xml | icat | 25 |
| appfiles.*outlook*.btinternet.net.xml | icat | 25 |
| appfiles.*outlook*.btopenworld.com.xml | icat | 25 |
| appfiles.*outlook*.flash.net.xml | icat | 25 |
| appfiles.*outlook*.gmail.com.xml | icat | 25 |
| appfiles.*outlook*.nl.rogers.com.xml | icat | 25 |
| appfiles.*outlook*.nvbell.net.xml | icat | 25 |
| appfiles.*outlook*.pacbell.net.xml | icat | 25 |
| appfiles.*outlook*.prodigy.net.xml | icat | 25 |
| appfiles.*outlook*.rogers.com.xml | icat | 25 |
| appfiles.*outlook*.sbcglobal.net.xml | icat | 25 |
| appfiles.*outlook*.snet.net.xml | icat | 25 |
| appfiles.*outlook*.swbell.net.xml | icat | 25 |
| appfiles.*outlook*.talk21.com.xml | icat | 25 |
| appfiles.*outlook*.wans.net.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.au.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.xml | icat | 25 |
| appfiles.*outlook*.yahoo.ca.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.id.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.in.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.jp.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.kr.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.nz.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.th.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.uk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.br.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.cn.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.hk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.mx.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.my.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.ph.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.sg.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.tw.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.vn.xml | icat | 25 |
| appfiles.*outlook*.yahoo.de.xml | icat | 25 |
| appfiles.*outlook*.yahoo.es.xml | icat | 25 |
| appfiles.*outlook*.yahoo.fr.xml | icat | 25 |
| appfiles.*outlook*.yahoo.hk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.ie.xml | icat | 25 |
| appfiles.*outlook*.yahoo.it.xml | icat | 25 |
| appfiles.*outlook*.yahoo.jp.xml | icat | 25 |
| appfiles.*outlook*.yahoo.no.xml | icat | 25 |
| appfiles.*outlook*.yahoo.pl.xml | icat | 25 |
| appfiles.*outlook*.yahoo.se.xml | icat | 25 |
| appfiles.*outlook*.fc39fbc8c85bcb43816b40b7d4c72f22_-_autodiscover.xml | icat | 129 |
| appfiles.*outlook*.firstrun.log | icat | 13 |
| appfiles.*outlook*.outlook.xml | icat | 48 |
| appfiles.*outlook*.outlookmui.xml | icat | 67 |
| appfiles.*outlook*.setup.xml | icat | 53 |
| appfiles.*outlook*.yahoo.com.ar.xml | icat | 25 |
| appfiles.*outlook*.ameritech.net.xml | icat | 25 |
| appfiles.*outlook*.btinternet.net.xml | icat | 25 |
| appfiles.*outlook*.btopenworld.com.xml | icat | 25 |
| appfiles.*outlook*.flash.net.xml | icat | 25 |
| appfiles.*outlook*.gmail.com.xml | icat | 25 |
| appfiles.*outlook*.nl.rogers.com.xml | icat | 25 |
| appfiles.*outlook*.nvbell.net.xml | icat | 25 |
| appfiles.*outlook*.pacbell.net.xml | icat | 25 |
| appfiles.*outlook*.prodigy.net.xml | icat | 25 |
| appfiles.*outlook*.rogers.com.xml | icat | 25 |
| appfiles.*outlook*.sbcglobal.net.xml | icat | 25 |
| appfiles.*outlook*.snet.net.xml | icat | 25 |
| appfiles.*outlook*.swbell.net.xml | icat | 25 |
| appfiles.*outlook*.talk21.com.xml | icat | 25 |
| appfiles.*outlook*.wans.net.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.au.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.xml | icat | 25 |
| appfiles.*outlook*.yahoo.ca.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.id.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.in.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.jp.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.kr.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.nz.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.th.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.uk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.br.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.cn.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.hk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.mx.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.my.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.ph.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.sg.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.tw.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.vn.xml | icat | 25 |
| appfiles.*outlook*.yahoo.de.xml | icat | 25 |
| appfiles.*outlook*.yahoo.es.xml | icat | 25 |
| appfiles.*outlook*.yahoo.fr.xml | icat | 25 |
| appfiles.*outlook*.yahoo.hk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.ie.xml | icat | 25 |
| appfiles.*outlook*.yahoo.it.xml | icat | 25 |
| appfiles.*outlook*.yahoo.jp.xml | icat | 25 |
| appfiles.*outlook*.yahoo.no.xml | icat | 25 |
| appfiles.*outlook*.yahoo.pl.xml | icat | 25 |
| appfiles.*outlook*.yahoo.se.xml | icat | 25 |
| appfiles.*outlook*.fc39fbc8c85bcb43816b40b7d4c72f22_-_autodiscover.xml | icat | 129 |
| appfiles.*outlook*.firstrun.log | icat | 13 |
| appfiles.*outlook*.outlook.xml | icat | 48 |
| appfiles.*outlook*.outlookmui.xml | icat | 67 |
| appfiles.*outlook*.setup.xml | icat | 53 |
| appfiles.*outlook*.yahoo.com.ar.xml | icat | 25 |
| appfiles.*outlook*.ameritech.net.xml | icat | 25 |
| appfiles.*outlook*.btinternet.net.xml | icat | 25 |
| appfiles.*outlook*.btopenworld.com.xml | icat | 25 |
| appfiles.*outlook*.flash.net.xml | icat | 25 |
| appfiles.*outlook*.gmail.com.xml | icat | 25 |
| appfiles.*outlook*.nl.rogers.com.xml | icat | 25 |
| appfiles.*outlook*.nvbell.net.xml | icat | 25 |
| appfiles.*outlook*.pacbell.net.xml | icat | 25 |
| appfiles.*outlook*.prodigy.net.xml | icat | 25 |
| appfiles.*outlook*.rogers.com.xml | icat | 25 |
| appfiles.*outlook*.sbcglobal.net.xml | icat | 25 |
| appfiles.*outlook*.snet.net.xml | icat | 25 |
| appfiles.*outlook*.swbell.net.xml | icat | 25 |
| appfiles.*outlook*.talk21.com.xml | icat | 25 |
| appfiles.*outlook*.wans.net.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.au.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.xml | icat | 25 |
| appfiles.*outlook*.yahoo.ca.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.id.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.in.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.jp.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.kr.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.nz.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.th.xml | icat | 25 |
| appfiles.*outlook*.yahoo.co.uk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.br.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.cn.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.hk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.mx.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.my.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.ph.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.sg.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.tw.xml | icat | 25 |
| appfiles.*outlook*.yahoo.com.vn.xml | icat | 25 |
| appfiles.*outlook*.yahoo.de.xml | icat | 25 |
| appfiles.*outlook*.yahoo.es.xml | icat | 25 |
| appfiles.*outlook*.yahoo.fr.xml | icat | 25 |
| appfiles.*outlook*.yahoo.hk.xml | icat | 25 |
| appfiles.*outlook*.yahoo.ie.xml | icat | 25 |
| appfiles.*outlook*.yahoo.it.xml | icat | 25 |
| appfiles.*outlook*.yahoo.jp.xml | icat | 25 |
| appfiles.*outlook*.yahoo.no.xml | icat | 25 |
| appfiles.*outlook*.yahoo.pl.xml | icat | 25 |
| appfiles.*outlook*.yahoo.se.xml | icat | 25 |
| chainsaw.hunt | chainsaw | 99 |
| evtx.windows_system32_winevt_logs_microsoft-windows-windows-firewall-with-advanced-security4connectionsecurity | eztools | 2 |
| evtx.windows_system32_winevt_logs_microsoft-windows-application-experience4program-inventory | eztools | 70 |
| evtx.windows_system32_winevt_logs_security | eztools | 1195 |
| evtx.windows_system32_winevt_logs_microsoft-windows-application-experience4program-inventory | eztools | 70 |
| regripper.cfreds_2015_data_leakage_pc | regripper | 0 |
| exiftool.metadata | exiftool | 2 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| composite.file_staging | composite | 578 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| exiftool.metadata | exiftool | 934 |
| exiftool.metadata | exiftool | 934 |
| composite.timeline | composite | 172 |
| composite.defense_evasion | composite | 200 |
| composite.lateral_movement | composite | 526 |
| composite.persistence | composite | 2438 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2551 |
| composite.execution | composite | 122 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
