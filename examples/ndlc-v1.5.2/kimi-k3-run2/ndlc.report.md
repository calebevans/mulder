# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T22:24:55.348518+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 330 evidence sources (65 disk, 265 other) | 1271 tool calls | 1.1 hours
**Results:** 31 findings (5 critical, 13 high) | 29 confirmed, 2 inference | 2 hypotheses ruled out
**Timeline:** 2014-12-01 to 2015-03-25

**Key Threats:**
- Sensitive "Secret Project" data copied to removable USB media (RM#1)
- Carved IOCs Reveal Personal Gmail Account and Cloud Storage as Exfiltration Destination
- Multi-session CD-R (RM#3) "IAMAN CD" contains Secret Project Data burned across 9 sessions with file deletion between sessions
- Cross-System Confirmation: 17 Masqueraded Secret Project Files Identical Across RM#2 USB, RM#3 Optical Disc, and PC Staging Areas
- Additional Accounts Created by Informant: admin11, ITechTeam, temporary (Insider-Created, Not External Backdoors)

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-03-22 to 2015-03-25): Timeline of data leakage events (2015-03-22 to 2015-03-25) (+13 related)
- **Persistence** (2015-01-20 to 2015-03-24): 17 Deleted Files with Masqueraded Extensions Concealing Office Documents on Removable Media RM2 (+4 related)
- **Command and Control** (2015-03-22 to 2015-03-24): Network share access to secured_drive containing Secret Project Data (+1 related)
- **Credential Access** (2015-03-24): RM#3 optical disc files use extension masquerading identical to RM#2 USB drive (+1 related)
- **Defense Evasion / Anti-Forensics** (2014-12-01 to 2015-03-24): Document Metadata and File Attribution - NIST Informant Source System (+2 related)
- **Other Activity** (2015-03-22): Additional NIST Email Persona: spy.conspirator@nist.gov Found in Bulk Extractor Output (+2 related)

**Tools:** search (526), get_raw_output (203), get_findings (73), submit_finding (47), open_case (30). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Sensitive "Secret Project" data copied to removable USB media (RM#1)** (2015-03-24T13:38:31 to 2015-03-24T21:05:38)


- **Carved IOCs Reveal Personal Gmail Account and Cloud Storage as Exfiltration Destination** (2015-03-23T17:24:31 to 2015-03-23T17:24:31)


- **Multi-session CD-R (RM#3) "IAMAN CD" contains Secret Project Data burned across 9 sessions with file deletion between sessions** (2015-03-24T20:54:16 to 2015-03-24T20:57:03Z)


- **Cross-System Confirmation: 17 Masqueraded Secret Project Files Identical Across RM#2 USB, RM#3 Optical Disc, and PC Staging Areas** (2015-03-24T20:54:16 to 2015-03-24T21:05:38)


- **Additional Accounts Created by Informant: admin11, ITechTeam, temporary (Insider-Created, Not External Backdoors)** (2015-03-22T15:51:54 to 2015-03-22T15:57:02)




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

1271 tool calls were executed across 26
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: CFReDS 2015 Data Leakage Case

## Background

This investigation concerns a data leakage incident involving a NIST employee identified by the username "informant" (email: iaman.informant@nist.gov) on a Windows workstation (hostname WIN-D9RGPJQ68G8). The evidence comprises four forensic disk images from the CFReDS 2015 Data Leakage dataset: the primary PC image (cfreds_2015_data_leakage_pc.E01), two USB removable media devices (RM#1 labeled "Authorized USB" with exFAT filesystem and volume serial 5c75-4d3e, and RM#2 labeled "IAMAN $_@" with FAT32 filesystem and volume ID 0xb4d85399), and one optical disc (RM#3 labeled "IAMAN CD", a UDF write-once CD-R with 9 VAT sessions). The investigation was conducted across 26 indexed evidence sources using 1271 tool invocations, yielding 31 findings (29 confirmed, 2 inferred, 2 negative), of which 5 are critical severity and 13 are high severity.

The workstation was connected to a corporate network with DHCP address 10.11.11.129 on subnet 10.11.11.0/24. A network file share at \\\\10.11.11.128\\secured_drive contained a "Secret Project Data" folder with sensitive business documents organized into subdirectories for design, proposal, progress, pricing decision, technical review, and final deliverables. The informant user account (SID S-1-5-21-2425377081-3129163575-2985601102-1000) was the primary active account and had been added to the local Administrators group. The investigation window spans from 2015-03-22 through 2015-03-25, with some artifacts dating back to December 2014 and January 2015 reflecting the original creation dates of the exfiltrated documents.

## Incident Timeline

The incident unfolded over four days, from March 22 through March 25, 2015, in distinct operational phases.

**Phase 1: Initial Access and Preparation (2015-03-22).** The informant account was created and added to the local Administrators group at 14:33:54 UTC, with the password hint "IAMAN" set. Within the next hour, the user accessed the network share at \\\\10.11.11.128\\secured_drive at 14:52:22 and browsed the Secret Project Data folder and its subdirectories. Google Chrome was installed at 15:11:21. Between 15:51:54 and 15:53:01, three additional user accounts were created in rapid succession: admin11 (RID 1001, added to Administrators), ITechTeam (RID 1002, added to Administrators but never logged in), and temporary (RID 1003, limited account). These accounts were created via Control Panel User Accounts, and all had "Password does not expire" set. The admin11 account was used for two logons, with the last at 15:57:02. A Windows Burn folder was created under the admin11 profile at 15:54:04, indicating preparation for optical media burning.

**Phase 2: Cloud Infrastructure Setup and Continued Reconnaissance (2015-03-23).** The Google Drive sync client (googledrivesync.exe) was downloaded at 19:56:30, with a Zone.Identifier alternate data stream confirming internet download. The Google Drive folder was created at Users\\informant\\Google Drive at 20:05:32. The user accessed drive.google.com via Internet Explorer at 20:34:09. The network share at \\\\10.11.11.128\\secured_drive was accessed again at 20:23:28, and the V: drive (mapped to the network share) was used to browse Secret Project Data at 20:27:24. Secret project files including pricing_decision.xlsx and final_meeting.pptx were accessed at 20:26-20:28.

**Phase 3: Data Staging and Multi-Vector Exfiltration (2015-03-24).** This was the most active day. Between 09:54:54 and 10:00:18 UTC, 17 files were copied to the RM#2 USB drive (FAT32, "IAMAN $_@") and subsequently deleted, ending up in $OrphanFiles. These files were masqueraded with false extensions to conceal their true content as Office documents. At 13:38:31, the RM#1 USB drive ("Authorized USB") was browsed at E:\\RM#1\\Secret Project Data, accessing subdirectories for design, proposal, progress, pricing decision, technical review, and final. The user browsed masqueraded files as ZIP archives at 14:01:29. At 19:47:48, the D: drive staging folder D:\\de was created, followed by D:\\pd, D:\\prop, and D:\\prog at 20:41:22. These abbreviated folder names correspond to design, pricing decision, proposal, and progress. Between 20:54:16 and 20:57:03, the RM#3 optical disc ("IAMAN CD") was burned across 9 sessions. The same 17 masqueraded files were written to the disc, then deleted between sessions. In the final session, three innocuous Windows sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) were burned at 20:57:00-20:57:03 to make the disc appear to contain only sample photos. Files were also moved to the Recycle Bin at 19:51:47 and 20:11:42.

**Phase 4: Anti-Forensic Cleanup and Resignation (2015-03-25).** On the day the investigation began, the informant executed a comprehensive anti-forensic cleanup. Eraser 6.2.0.2962 was downloaded and executed at 14:50:14, with Eraser.exe run at 15:12:28. CCleaner64.exe was executed at 15:15:50. The Google Drive sync databases (snapshot.db, sync_config.db) were deleted to destroy evidence of cloud uploads. The Google Drive folder was accessed at 15:20:59, and Google Drive sync executed at 15:21:30. A resignation letter (Resignation_Letter_(Iaman_Informant).docx and .xps) was written at approximately 15:28. CCleaner language DLLs were found in $OrphanFiles, indicating cleanup after cleanup. The composite recovery analysis identified 2,223 deleted files on the system and flagged that secure delete tools were detected, meaning some deleted files may be unrecoverable.

## Key Findings

### Data Exfiltration via Removable Media

The investigation confirmed three distinct physical exfiltration vectors, all containing the same set of sensitive Secret Project Data files. The RM#1 USB drive ("Authorized USB", exFAT) contained the Secret Project Data folder with original filenames including [secret_project]_detailed_proposal.docx (35MB), [secret_project]_design_concept.ppt, [secret_project]_final_meeting.pptx, and (secret_project)_pricing_decision.xlsx. The RM#2 USB drive ("IAMAN $_@", FAT32) contained 17 deleted files in $OrphanFiles with masqueraded extensions concealing Office documents. The RM#3 optical disc ("IAMAN CD", UDF multi-session CD-R) contained the same 17 masqueraded files burned across 9 sessions with inter-session deletion. The identical file sizes and timestamps across all three media confirm these are the same files, totaling approximately 104 MB of concealed data.

### Extension Masquerading for Data Concealment

Seventeen files were renamed with false extensions to disguise their true content as Office documents. Files named with media extensions (.amr, .avi), image extensions (.jpg, .png, .gif, .svg), archive extensions (.zip, .7z), text extensions (.txt), database extensions (.db), and OneNote extensions (.one) actually contained OLE compound documents and Office Open XML files (docx, xlsx, pptx). Specific examples include winter_storm.amr (actually OLE, 14.5MB), a_gift_from_you.gif (actually DOCX, 35.2MB), and new_years_day.jpg (actually XLSX, 10.2MB). This technique was designed to evade Data Loss Prevention (DLP) systems and casual inspection. No steganographic content was detected; the concealment was purely through extension masquerading.

### Cloud Exfiltration via Google Drive

Google Drive sync client was installed and configured with the personal Gmail account iaman.informant.personal@gmail.com, distinct from the corporate email iaman.informant@nist.gov. URL artifacts show the user accessed Google Account login pages with the personal email embedded, including a path to "/settings/storage" indicating Google Drive storage settings access. The Google Drive sync databases were subsequently deleted, consistent with anti-forensic cleanup to hide evidence of what files were uploaded. While no network capture data directly confirms the upload, the combination of client installation, personal account configuration, folder access during the exfiltration window, and database destruction provides strong circumstantial evidence of cloud exfiltration.

### Backdoor Account Creation

Three additional user accounts were created on 2015-03-22 within a two-minute window: admin11 (RID 1001, Administrators member, actively used), ITechTeam (RID 1002, Administrators member, never logged in, possibly a backup account), and temporary (RID 1003, limited account). All had "Password does not expire" set. These accounts were created via Control Panel User Accounts, and their creation coincided with the start of the data exfiltration activity, indicating premeditation and intent to maintain persistent access.

### Anti-Forensic Evidence Destruction

On 2015-03-25, the day the investigation began, the user downloaded and executed Eraser 6.2.0.2962 and CCleaner64.exe. Web search history revealed extensive research into anti-forensic techniques including searches for "anti-forensic tools" (n=85), "ccleaner" (n=65), "eraser" (n=51), "how to delete data" (n=5), and "data recovery tools" (n=3). The user also searched for "information leakage cases" (n=47), "how to leak a secret" (n=6), "intellectual property theft" (n=6), and "DLP DRM" (n=90), demonstrating clear premeditation. The Google Drive sync databases were deleted, and CCleaner language DLLs were found in $OrphanFiles, indicating cleanup after cleanup. The composite recovery analysis identified 2,223 deleted files and flagged that secure delete tools may have rendered some files unrecoverable.

### Multi-Session CD-R Concealment Technique

The RM#3 optical disc employed a sophisticated multi-session deletion technique. The disc has 9 VAT (Virtual Allocation Table) generations, with the Secret Project Data files burned in sessions -1 through -7 and then deleted between sessions. The final session (session 0) contains only three innocuous Windows sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) created at 20:57:00-20:57:03, approximately one minute after the last sensitive files were burned. This technique makes the disc appear to contain only sample photos when inserted into a computer, while the sensitive data remains recoverable from earlier sessions. The user searched for "cd burning method" (n=64 searches), demonstrating intent to use this technique.

### Email Personas and Communications

Multiple email identities were associated with the informant: the corporate account iaman.informant@nist.gov, the personal Gmail account iaman.informant.personal@gmail.com, and an additional persona spy.conspirator@nist.gov found in bulk extractor output. An Outlook OST file containing the NIST email account data was identified, which would contain all emails, contacts, and calendar items. Additional NIST contacts found in email metadata include 645mtgs@xchange.nist.gov (Division 645) and wei.yu@nist.gov (Yu, Wei, office 222/A218).

## Threat Intelligence and Attribution

The evidence overwhelmingly attributes this data leakage to the insider user "informant" (iaman.informant@nist.gov). Multiple independent evidence sources converge on this attribution: the volume labels "IAMAN $_@" (RM#2) and "IAMAN CD" (RM#3) directly match the informant's password hint "IAMAN" and email username. The personal Gmail account iaman.informant.personal@gmail.com was found in URL artifacts associated with Google Drive access. The spy.conspirator@nist.gov email persona further strengthens attribution. All activity was performed under the informant user account or accounts created by the informant.

The TTP profile is consistent with a malicious insider threat rather than an external attacker. Key indicators include: use of legitimate system access (no exploitation of vulnerabilities), creation of backdoor accounts for persistent access, use of personal cloud storage for exfiltration, extension masquerading to evade DLP, multi-session CD burning with inter-session deletion, comprehensive anti-forensic cleanup upon detection, and premeditated research into data leakage methods and anti-forensic tools. The 15 MITRE ATT&CK techniques identified span Collection (T1039, T1074.001), Exfiltration (T1052.001, T1567.002), Defense Evasion (T1036, T1036.002, T1070.002, T1070.004, T1070.006), Persistence (T1136, T1136.001, T1098), and Resource Development (T1583.001).

This is not consistent with any known external threat actor group. The behavior pattern is characteristic of an insider threat with authorized access to sensitive data who deliberately exfiltrated that data to personal storage media and cloud services.

## Impact Assessment

The incident resulted in the confirmed exfiltration of approximately 104 MB of sensitive "Secret Project Data" across at least three physical media (two USB drives and one optical disc) and likely to a personal Google Drive cloud storage account. The exfiltrated data includes detailed project proposals (35.2MB), design documents (14.5MB and 16.4MB), pricing decisions (10.2MB XLSX and others), technical review documents (multiple diary files totaling approximately 4.7MB), progress reports, and final meeting presentations. The data was copied to removable media that could have been physically removed from the premises, and the Google Drive upload means the data may persist in cloud storage beyond organizational control.

One workstation (WIN-D9RGPJQ68G8) was directly compromised, with four user accounts (informant, admin11, ITechTeam, temporary) involved in the incident. The network share at \\\\10.11.11.128\\secured_drive was the source of the exfiltrated data, and other systems on the 10.11.11.0/24 subnet may be at risk if the backdoor accounts were used for lateral movement. The anti-forensic cleanup destroyed or attempted to destroy evidence, with 2,223 deleted files identified and secure deletion tools potentially rendering some files unrecoverable. The full scope of data uploaded to Google Drive cannot be determined from the available evidence due to the deletion of sync databases.

## Immediate Tactical Containment

1. Isolate the workstation WIN-D9RGPJQ68G8 (DHCP IP 10.11.11.129) from the network immediately to prevent further data access or exfiltration.
2. Disable all four user accounts: informant (SID S-1-5-21-2425377081-3129163575-2985601102-1000), admin11 (RID 1001), ITechTeam (RID 1002), and temporary (RID 1003).
3. Block the personal Gmail account iaman.informant.personal@gmail.com at the network perimeter and contact Google to preserve and potentially suspend the associated Google Drive account.
4. Preserve and secure the network share at \\\\10.11.11.128\\secured_drive and audit access logs for all users who accessed the Secret Project Data folder.
5. Search for and secure any additional copies of the RM#2 USB drive (volume label "IAMAN $_@", FAT32, volume ID 0xb4d85399) and RM#3 optical disc (volume label "IAMAN CD").
6. Block the file hashes of all 17 masqueraded files at the network perimeter and endpoint protection to detect any further distribution.
7. Preserve the Outlook OST file associated with iaman.informant@nist.gov for email communication analysis.
8. Review and audit all access by NIST personnel 645mtgs@xchange.nist.gov (Division 645) and wei.yu@nist.gov to determine if they had any involvement or knowledge of the data leakage.
9. Initiate legal hold on all Google services associated with iaman.informant.personal@gmail.com and spy.conspirator@nist.gov.
10. Image and preserve the workstation's hard drive and all connected storage devices before any further anti-forensic activity can occur.

## Strategic Remediation

**Root Cause 1: Unrestricted Removable Media Access.** The informant was able to connect multiple USB drives and an optical disc writer to the workstation and copy sensitive data without any technical controls preventing or detecting the transfers. The RM#1 drive was labeled "Authorized USB," suggesting a policy existed for authorized media, but the RM#2 drive ("IAMAN $_@") was clearly unauthorized personal media that was not blocked. The organization lacked endpoint DLP controls capable of detecting the file copy operations to removable media, and the extension masquerading technique (finding f_2d443a83) would have evaded simple file-type-based DLP rules. Remediation requires implementing endpoint DLP with content inspection (not just extension checking), USB device whitelisting that blocks unauthorized devices, and optical drive write restrictions on systems handling sensitive data.

**Root Cause 2: Unmonitored Cloud Storage Access.** The informant installed Google Drive sync client and configured it with a personal Gmail account (iaman.informant.personal@gmail.com) without detection (finding f_1e6eb0a1). The organization had no cloud access security broker (CASB) or web filtering rules to block or alert on personal cloud storage usage from corporate workstations. The Google Drive sync databases were deleted before investigators could determine what was uploaded. Remediation requires deploying a CASB solution to monitor and control cloud storage usage, blocking unauthorized cloud storage domains at the web proxy, and alerting on installation of file synchronization clients on workstations with access to sensitive data.

**Root Cause 3: Excessive Local Administrative Privileges.** The informant account was a member of the local Administrators group, which allowed the creation of three backdoor accounts (admin11, ITechTeam, temporary) with administrative privileges (finding f_cec71d38). These backdoor accounts had "Password does not expire" set and could have been used for persistent access even after the informant's departure. Remediation requires implementing the principle of least privilege by removing local administrative rights from standard user accounts, enabling LAPS (Local Administrator Password Solution) for managing local admin passwords, and alerting on Security Event ID 4732 (user added to local admin group) and 4720 (user account created) for real-time detection of unauthorized account creation.

**Root Cause 4: No Network Share Access Monitoring.** The informant accessed the sensitive network share at \\\\10.11.11.128\\secured_drive over two days (2015-03-22 and 2015-03-23) without triggering any alerts (finding f_bfb927fd). The share contained Secret Project Data accessible to the informant, and there was no file access auditing or anomaly detection to flag the bulk browsing of sensitive subdirectories. Remediation requires enabling Windows File Server auditing on sensitive shares, implementing a file activity monitoring solution to detect bulk access patterns, and restricting access to the Secret Project Data folder to only those personnel with a documented need-to-know.

**Root Cause 5: Delayed Incident Detection.** The anti-forensic cleanup (Eraser, CCleaner) was executed on 2015-03-25, the same day the investigation began, suggesting the informant was aware of the investigation and had time to attempt evidence destruction (finding f_558fb38f). The data exfiltration occurred on 2015-03-24, one day before the investigation started, meaning the organization detected the incident approximately 24-48 hours after the initial data theft. Remediation requires implementing real-time alerting on sensitive file access patterns, USB device connections, and cloud storage synchronization activity to reduce the detection-to-response window.

**Root Cause 6: Insufficient Anti-Forensic Defenses.** The informant was able to download and execute anti-forensic tools (Eraser, CCleaner) without any application whitelisting or execution prevention controls blocking them (finding f_e84b2b7a). The user also researched anti-forensic techniques extensively before executing the cleanup. Remediation requires implementing application whitelisting (e.g., AppLocker or Windows Defender Application Control) to prevent execution of unauthorized software, particularly known anti-forensic tools, and deploying endpoint detection and response (EDR) with behavioral analytics to detect and alert on anti-forensic tool execution patterns.

## Conclusion

**Q1. What systems were compromised?** One workstation (WIN-D9RGPJQ68G8, DHCP 10.11.11.129) was directly compromised. The network file share at \\\\10.11.11.128\\secured_drive was accessed as the data source. Four user accounts were involved: informant (primary), admin11, ITechTeam, and temporary (backdoor accounts). Three physical media devices were used for exfiltration: RM#1 USB ("Authorized USB"), RM#2 USB ("IAMAN $_@"), and RM#3 optical disc ("IAMAN CD"). A personal Google Drive account (iaman.informant.personal@gmail.com) was used for cloud exfiltration.

**Q2. How did the attacker gain initial access?** This was an insider threat. The informant had legitimate authorized access to the workstation and the network share containing Secret Project Data. No external exploitation or unauthorized access was involved. The informant account was created and added to the Administrators group on 2015-03-22 at 14:33:54, and the network share was first accessed at 14:52:22 on the same day.

**Q3. What lateral movement occurred?** No traditional lateral movement to other systems was observed in the evidence. The informant accessed the network share at \\\\10.11.11.128\\secured_drive from the workstation, which constitutes network resource access but not lateral movement in the traditional sense. The backdoor accounts (admin11, ITechTeam, temporary) were created on the local workstation and could have been used for persistent access but there is no evidence they were used to access other systems.

**Q4. What persistence mechanisms were installed?** Three backdoor user accounts were created: admin11 (RID 1001, Administrators member, actively used), ITechTeam (RID 1002, Administrators member, never logged in, likely a backup), and temporary (RID 1003, limited account). All had "Password does not expire" set. These accounts would have provided persistent administrative access to the workstation even after the informant's departure or account disablement.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes, approximately 104 MB of sensitive Secret Project Data was confirmed exfiltrated across three physical media (RM#1 USB, RM#2 USB, RM#3 optical disc). The data includes detailed project proposals (35.2MB DOCX), design documents (14.5MB OLE and 16.4MB PPTX), pricing decisions (10.2MB XLSX and others), technical review documents (approximately 4.7MB across 6 diary files), progress reports, and final meeting presentations. Additionally, strong circumstantial evidence indicates the data was uploaded to a personal Google Drive account (iaman.informant.personal@gmail.com), though the exact scope of the cloud upload cannot be determined due to deletion of sync databases.

**Q6. What is the full timeline of the incident?** The incident spans four days: 2015-03-22 (account creation, network share access, backdoor account creation), 2015-03-23 (Google Drive setup, continued network share reconnaissance), 2015-03-24 (data staging, USB copy to RM#2 at 09:54-10:00, RM#1 USB browsing at 13:38, D: drive staging at 19:47-20:41, CD burn to RM#3 at 20:54-20:57), and 2015-03-25 (anti-forensic cleanup with Eraser and CCleaner at 14:50-15:15, Google Drive sync at 15:21, resignation letter at 15:28). The original documents were created/modified between 2014-12-01 and 2015-01-23.

**Q7. What is the total scope and business impact?** The incident resulted in the loss of approximately 104 MB of sensitive Secret Project Data across physical media and potentially to personal cloud storage. The data includes pricing decisions, technical designs, project proposals, and progress reports that represent significant intellectual property. The anti-forensic cleanup destroyed or attempted to destroy evidence, with 2,223 deleted files identified. The informant's resignation on the day of the investigation suggests premeditated departure after the data theft. The presence of NIST contacts (645mtgs@xchange.nist.gov, wei.yu@nist.gov) in email metadata raises the possibility of a broader conspiracy, though no direct evidence of colleague involvement was found.

**Q8. What are the recommended remediation actions?** Six strategic remediation actions are recommended, each tied to a specific root cause identified in the evidence: (1) implement endpoint DLP with content inspection and USB device whitelisting to prevent unauthorized removable media usage; (2) deploy CASB and web filtering to block personal cloud storage from corporate workstations; (3) enforce least privilege by removing local admin rights and implementing LAPS; (4) enable file access auditing and anomaly detection on sensitive network shares; (5) implement real-time alerting on sensitive file access, USB connections, and cloud sync activity; and (6) deploy application whitelisting to prevent execution of anti-forensic tools. These recommendations are detailed in the Strategic Remediation section above.


---

## Overview

| | |
|---|---|
| Findings | **31** (29 confirmed, 2 inference) |
| Severity | 5 critical, 13 high, 8 medium, 1 low, 4 info |
| Sources | 26 evidence sources across 1271 tool calls |
| Ruled Out | 2 hypotheses tested and rejected |


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
| 2014-12-01T14:50:26 | Document Metadata and File Attribution - NIST Informant Source System | MEDIUM | exiftool.metadata, tsk.fsstat, bulk.email, tsk.masquerade |
| 2015-01-20T14:18:06 | 17 Deleted Files with Masqueraded Extensions Concealing Office Documents on Removable Media RM2 | HIGH | registry.sam, tsk.filelist, tsk.fsstat, tsk.masquerade, tsk.timeline |
| 2015-02-15T16:51:38 | Secret Project Data files on RM#1 USB drive with original filenames | HIGH | tsk.timeline, tsk.fsstat, tsk.filelist |
| 2015-03-22T14:33:54 | Windows Event Logs reveal account creation and privilege escalation during data leakage | HIGH | ez.mft, hayabusa.alerts |
| 2015-03-22T14:33:54 | User account "informant" was the primary active account during data leakage | MEDIUM | registry.system, hayabusa.alerts, registry.ntuser.informant |
| 2015-03-22T14:33:54 | Additional NIST Email Persona: spy.conspirator@nist.gov Found in Bulk Extractor Output | MEDIUM | bulk.email |
| 2015-03-22T14:33:54 | Outlook Offline Storage Table (OST) File Contains NIST Email Account Data | MEDIUM | bulk.domain |
| 2015-03-22T14:33:54 | Additional NIST Contacts Found in Email Metadata: 645mtgs@xchange.nist.gov and wei.yu@nist.gov | LOW | bulk.email |
| 2015-03-22T14:33:54 | Timeline of data leakage events (2015-03-22 to 2015-03-25) | INFO | registry.sam, registry.usrclass.informant, registry.ntuser.informant, ez.mft, hayabusa.alerts, tsk.timeline |
| 2015-03-22T14:33:54 | Complete Chronological Sequence of Events: Network Share Access Through Anti-Forensic Cleanup | INFO | registry.sam, registry.usrclass.informant, optical.listing, tsk.masquerade, ez.mft, composite.recovery, composite.timeline |
| 2015-03-22T14:52:22 | Network share access to secured_drive containing Secret Project Data | HIGH | registry.usrclass.informant |
| 2015-03-22T14:52:22 | Network Share Access Corroborated by Multiple Evidence Sources | HIGH | registry.usrclass.informant, bulk.domain |
| 2015-03-22T15:51:54 | Additional Accounts Created by Informant: admin11, ITechTeam, temporary (Insider-Created, Not External Backdoors) | CRITICAL | registry.sam, registry.usrclass.informant |
| 2015-03-22T15:54:04 | CD Burning Software: Windows Built-in IMAPI Used for Multi-Session RM#3 Disc | MEDIUM | ez.mft, optical.listing |
| 2015-03-23T17:24:31 | Carved IOCs Reveal Personal Gmail Account and Cloud Storage as Exfiltration Destination | CRITICAL | bulk.email, bulk.url, bulk.url_searches |
| 2015-03-23T19:56:30 | Google Drive Sync Client Installed and Configured - Exfiltration to iaman.informant.personal@gmail.com (Circumstantial) | HIGH | tsk.filelist, registry.system, bulk.email, enrichment.iocs, registry.usrclass.informant |
| 2015-03-23T20:02:43 | Web browsing activity related to cloud storage and anti-forensic research | HIGH | bulk.url, ez.mft, registry.ntuser.informant, tsk.filelist, tsk.timeline |
| 2015-03-24T13:38:31 | Sensitive "Secret Project" data copied to removable USB media (RM#1) | CRITICAL | tsk.masquerade, registry.usrclass.informant, tsk.filelist, tsk.fsstat, tsk.timeline |
| 2015-03-24T13:38:31 | RM#1 'Authorized USB' Drive Used for Both Legitimate and Exfiltration Purposes | HIGH | registry.usrclass.informant, optical.listing, tsk.masquerade |
| 2015-03-24T14:50:14Z | Anti-forensic research and tool acquisition intent | HIGH | bulk.url, bulk.url_searches |
| 2015-03-24T19:47:48 | D: Drive (BD-RE Optical) Staging Area Used as Intermediate Step Before CD Burn | HIGH | registry.usrclass.informant, optical.listing, bulk.domain |
| 2015-03-24T19:51:47 | Files deleted to Recycle Bin and beyond on 2015-03-24 | MEDIUM | ez.mft, tsk.masquerade, tsk.filelist, registry.usrclass.informant |
| 2015-03-24T20:54:16 | Multi-session CD-R (RM#3) "IAMAN CD" contains Secret Project Data burned across 9 sessions with file deletion between sessions | CRITICAL | bulk.url, optical.listing, registry.ntuser.informant |
| 2015-03-24T20:54:16 | Cross-System Confirmation: 17 Masqueraded Secret Project Files Identical Across RM#2 USB, RM#3 Optical Disc, and PC Staging Areas | CRITICAL | tsk.masquerade, optical.listing, registry.usrclass.informant, tsk.filelist |
| 2015-03-24T20:54:16Z | RM#3 optical disc files use extension masquerading identical to RM#2 USB drive | HIGH | optical.listing, tsk.masquerade |
| 2015-03-24T20:54:16Z | IOCs carved from RM#3 optical disc reveal document metadata and email addresses | MEDIUM | bulk.email, bulk.domain, bulk.url, bulk.rfc822, bulk.url_services |
| 2015-03-24T20:54:16Z | RM#3 optical disc volume label "IAMAN CD" links to informant identity and burn timeline | MEDIUM | optical.listing, registry.sam |
| 2015-03-25T14:50:14 | Anti-forensic tools (Eraser, CCleaner) installed and executed to destroy evidence | HIGH | registry.ntuser.informant, ez.mft, tsk.timeline, bulk.url |
| 2015-03-25T14:57:31 | Anti-Forensic Cleanup: Eraser and CCleaner Used to Destroy Evidence | HIGH | composite.recovery, ez.shimcache, tsk.filelist, optical.listing, tsk.masquerade |




---

## Hypotheses Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No Steganographic Content - Concealment via Extension Masquerading, Not Steganography** : Analysis of the steganographic and embedded content evidence reveals that the data concealment on RM2 is achieved through extension masquerading, not steganography.

Steganography Detection:
- The...

- **No steganography or malware detected on RM#3 optical disc** : Steganography detection (stegdetect) and YARA malware scanning were run against the RM#3 optical disc image (cfreds_2015_data_leakage_rm3_type3.E01) and returned no results.

**Steganography:**...



---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Sensitive "Secret Project" data copied to removable USB media (RM#1)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:38:31 to 2015-03-24T21:05:38 |
| **Sources** | tsk.masquerade, registry.usrclass.informant, tsk.filelist, tsk.fsstat, tsk.timeline |
| **Evidence Refs** | tc_6f08c30a, tc_168fd4d4, tc_7474aab9, tc_0525c3c4 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


The informant user copied sensitive "Secret Project Data" files to a removable USB drive labeled "Authorized USB" (volume serial 5c75-4d3e, exFAT filesystem). Shellbags show the user browsed E:\RM#1\Secret Project Data on 2015-03-24 13:38:31 and accessed subdirectories including design, proposal, progress, pricing decision, technical review, and final. The Secret Project Data folder on the USB contained files including [secret_project]_detailed_proposal.docx (35MB), [secret_project]_design_concept.ppt, [secret_project]_final_meeting.pptx, and (secret_project)_pricing_decision.xlsx. The same data was also accessed from a network share at \\10.11.11.128\secured_drive\Secret Project Data and copied to the local D: drive (D:\de, D:\tr, D:\pd, D:\prop, D:\prog folders).



### 2. [CRITICAL] Carved IOCs Reveal Personal Gmail Account and Cloud Storage as Exfiltration Destination

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T17:24:31 to 2015-03-23T17:24:31 |
| **Sources** | bulk.email, bulk.url, bulk.url_searches |
| **Evidence Refs** | tc_27f7fa15, tc_85461772, tc_a43f4b87, tc_b24fc511, tc_d4d7ee85 |
| **ATT&CK** | [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Carved IOCs from the PC image (source: bulk.url, bulk.email) reveal the destination/recipient of the leaked data and the user's research into data leakage methods.

Key IOC - Personal Gmail Account:
The URL data (source: bulk.url, window 46716-46717) contains Google Account login URLs with the email address "iaman.informant.personal@gmail.com" embedded:
- https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fwww.google.com%2Fsettings%2Fstorage%3Fhl%3Den_US&sacu=1&passive=1209600#Email=iaman.informant.personal%40gmail.com
- https://accounts.google.com/AccountChooser?Email=iaman.informant.personal%40gmail.com&continue=https%3A//www.google.com/settings/stora

The URL path "/settings/storage" indicates the user was accessing Google Drive storage settings, suggesting the leaked data was uploaded to Google Drive (cloud storage exfiltration).

Corporate Email:
The email data (source: bulk.email) contains the corporate email "iaman.informant@nist.gov" and "iaman@nist.gov", identifying the user as a NIST informant.

Search History - Intent to Leak Data:
The URL search history (source: bulk.url_searches) reveals the user researched data leakage and anti-forensic techniques:
- "information leakage cases" (n=47)
- "how to leak a secret" (n=6)
- "intellectual property theft" (n=6)
- "leaking confidential information" (n=2)
- "data leakage methods" (n=1)
- "DLP DRM" (Data Loss Prevention) (n=90)
- "anti-forensic tools" (n=85)
- "how to delete data" (n=5)
- "data recovery tools" (n=3)
- "cloud storage" (n=6)
- "google drive" (n=10)
- "ccleaner" (n=65)
- "eraser" (n=51)
- "e-mail investigation" (n=88)
- "Forensic Email Investigation" (n=78)
- "external device and forensics" (n=65)
- "cd burning method" (n=64)

This search history demonstrates clear intent to leak data, research into anti-forensic tools (CCleaner, Eraser), and investigation into how to delete data and evade detection. The combination of the personal Gmail account, Google Drive access, and the search history strongly indicates the leaked data was exfiltrated to the user's personal Google Drive account.

**Merged findings:**
- **Personal Gmail account used for Google Drive exfiltration** (f_d64d24e2, critical, confirmed): Bulk extractor URL data reveals the user accessed Google Account login pages with a personal Gmail account: iaman.informant.personal@gmail.com. The URLs include: (1) https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fwww.google.com%2Fsettings%2Fstorage%3Fhl%3Den_US&sacu=1&passive=1209600#Email=iaman.informant.personal%40gmail.com - the "/settings/storage" path indicates Google Drive storage settings access. (2) https://accounts.google.com/AccountChooser?Email=iaman.informant.personal%40gmail.com&continue=https%3A//www.google.com/settings/stora. This personal Gmail account is distinct from the corporate email iaman.informant@nist.gov. The user also searched for "google drive" (n=10) and "cloud storage" (n=6) in their search history. This strongly suggests the leaked Secret Project Data was exfiltrated to the user's personal Google Drive account.

**Affected Systems:** bulk.email, bulk.url, bulk.url_searches



### 3. [CRITICAL] Multi-session CD-R (RM#3) "IAMAN CD" contains Secret Project Data burned across 9 sessions with file deletion between sessions

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T20:57:03Z |
| **Sources** | bulk.url, optical.listing, registry.ntuser.informant |
| **Evidence Refs** | tc_2b7fa20b, tc_374aea29, tc_3bddfaac, tc_8279b429, tc_841c13f8, tc_c3554952, tc_eee89db9 |
| **ATT&CK** | [T1036.002](https://attack.mitre.org/techniques/T1036/002/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


The optical disc RM#3 (cfreds_2015_data_leakage_rm3_type3.E01) is a UDF write-once CD-R with volume label "IAMAN CD", 52,513 sectors, and 9 VAT generations (sessions). The disc contains the same Secret Project Data files found on RM#1 and RM#2, burned across multiple sessions with files deleted between sessions to conceal earlier burns.

**Session Structure (9 VAT generations):**
- Session 0 (final): Only 3 Windows sample images remain visible: Koala.jpg (780KB), Penguins.jpg (777KB), Tulips.jpg (620KB) - all created 2015-03-24 20:57:00-20:57:03Z, modified 2009-07-14 (original Windows sample files)
- Sessions -1 through -7: Contain the Secret Project Data files in both abbreviated (de, pd, prog, prop, tr) and full (design, pricing decision, progress, proposal, technical review) directory names

**Files burned and deleted across sessions:**
- /design/winter_storm.amr (14.5MB, actually OLE) and /design/winter_whether_advisory.zip (16.4MB, actually PPTX) - deleted in session -7
- /pricing decision/my_favorite_cars.db (1.3MB, OLE), my_favorite_movies.7z (100KB, XLSX), new_years_day.jpg (10.2MB, XLSX), super_bowl.avi (10.3MB, OLE) - deleted in session -6
- /progress/my_friends.svg (58KB, OLE), my_smartphone.png (4.4MB, DOCX), new_year_calendar.one (27KB, DOCX) - deleted in session -5
- /proposal/a_gift_from_you.gif (35.2MB, DOCX), landscape.png (6.5MB, DOCX) - deleted in session -4
- /technical review/diary_#1d.txt (121KB, DOCX), diary_#1p.txt (458KB, PPTX), diary_#2d.txt (659KB, DOCX), diary_#2p.txt (1.2MB, OLE), diary_#3d.txt (2.4MB, OLE), diary_#3p.txt (325KB, OLE) - deleted in session -3

**Key evidence:**
- All files were created on the disc on 2015-03-24 between 20:54:16 and 20:55:46Z
- Original file modification times range from 2014-12-01 to 2015-01-23
- The same files were also copied to RM#2 (FAT32 "IAMAN $_@") on 2015-03-24 09:54-10:00Z
- Volume label "IAMAN CD" matches the informant's password hint "IAMAN" and email iaman.informant@nist.gov
- The final session (session 0) shows only innocuous Windows sample images, suggesting the user attempted to make the disc appear to contain only sample photos

This is a multi-session CD-R used to exfiltrate Secret Project Data, with files deleted between sessions to conceal the earlier burns. The disc was burned on 2015-03-24, the same day as the RM#2 USB copy operation.

**Merged findings:**
- **RM#3 optical disc final session shows only innocuous Windows sample images - deliberate concealment** (f_d3e70d11, high, confirmed): The final session (session 0) of the RM#3 optical disc contains only 3 Windows sample images: Koala.jpg (780,831 bytes), Penguins.jpg (777,835 bytes), and Tulips.jpg (620,888 bytes). These are standard Windows 7 sample photos with original modification dates of 2009-07-14 (Windows 7 RTM build date).

The files were created on the disc on 2015-03-24 at 20:57:00-20:57:03Z, approximately 1-2 minutes after the last Secret Project Data files were burned (20:55:46Z). This timing suggests the user deliberately burned these innocuous images as the final session to make the disc appear to contain only sample photos when inserted into a computer.

The previous sessions (sessions -1 through -7) contained the actual Secret Project Data files, which were deleted between sessions. On a standard CD-R, deleted files from earlier sessions are not visible in the final session's filesystem view, but the data remains on the disc and can be recovered through forensic analysis of the multi-session structure.

This is a deliberate concealment technique: the user burned the sensitive data across multiple sessions, deleted the files between sessions, and then burned innocuous Windows sample images as the final visible session. Anyone casually examining the disc would see only the sample photos, while the sensitive data remains recoverable from the earlier sessions.
- **Multi-session CD-R deletion technique used to conceal Secret Project Data burns** (f_bd73900e, high, confirmed): The RM#3 optical disc uses a sophisticated multi-session deletion technique to conceal the sensitive data burns. The disc has 9 VAT generations (sessions), with the following structure:

**Session 0 (final, visible):** Only 3 Windows sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) - created 2015-03-24 20:57:00-20:57:03Z

**Sessions -1 through -7 (deleted, recoverable):** Contain the Secret Project Data files in both abbreviated and full directory names:
- Session -1: Abbreviated names (de, pd, prog, prop, tr) with all 17 masqueraded files
- Session -3: /technical review with diary files
- Session -4: /proposal with a_gift_from_you.gif, landscape.png
- Session -5: /progress with my_friends.svg, my_smartphone.png, new_year_calendar.one
- Session -6: /pricing decision with my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi
- Session -7: /design with winter_storm.amr, winter_whether_advisory.zip

**Technique:** On a multi-session CD-R, each new session can mark files from previous sessions as "deleted" without actually erasing the data. The data remains on the disc and can be recovered through forensic analysis of the VAT (Virtual Allocation Table) generations. The user burned the sensitive data across multiple sessions, deleted the files between sessions, and then burned innocuous Windows sample images as the final visible session.

This is a deliberate anti-forensic technique: anyone casually examining the disc would see only the sample photos, while the sensitive data remains recoverable from the earlier sessions. The technique is consistent with the user's research into "cd burning method" (n=64 searches) and anti-forensic tools.
- **Optical media (BD-RE "IAMAN CD") used to burn Secret Project Data with masqueraded filenames** (f_7f5cc06a, high, confirmed): A BD-RE (Blu-ray Disc Rewritable) optical media with volume label "IAMAN CD" was used to burn the Secret Project Data files. The optical media contains the same masqueraded files found on RM#2 (USB drive), organized in the same directory structure: /design (winter_storm.amr, winter_whether_advisory.zip), /pricing decision (my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi), /progress (my_friends.svg, my_smartphone.png, new_year_calendar.one), /proposal (a_gift_from_you.gif, landscape.png), and /technical review (diary_#1d.txt through diary_#3p.txt). The files were burned to the optical media on 2015-03-24 between 20:54:16 and 20:55:46 UTC. The media also contains three sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) created at 20:57:00-20:57:03, likely as cover files. The UDF filesystem shows 9 sessions (VAT generations), indicating multiple write operations. The volume label "IAMAN CD" directly links to the informant user (password hint "IAMAN", email iaman.informant@nist.gov). The RecentDocs registry shows "BD-RE Drive (D:) IAMAN CD" was accessed, confirming the user interacted with this optical media. This represents a third physical exfiltration vector in addition to the USB drives (RM#1 and RM#2).
- **Optical media (CD/DVD) "IAMAN CD" used for data exfiltration with masqueraded files** (f_434c419d, critical, confirmed): A UDF write-once optical media (CD/DVD) with volume label "IAMAN CD" was discovered containing the same masqueraded Secret Project files found on RM#2. The optical media contains 9 sessions (VAT generations) showing the progression of data being written and then deleted. The files were organized in directories matching the Secret Project structure: /design, /pricing decision, /progress, /proposal, /technical review, and abbreviated versions /de, /pd, /prog, /prop, /tr. All 17 masqueraded files (winter_storm.amr, winter_whether_advisory.zip, my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi, my_friends.svg, my_smartphone.png, new_year_calendar.one, a_gift_from_you.gif, landscape.png, diary_#1d.txt, diary_#1p.txt, diary_#2d.txt, diary_#2p.txt, diary_#3d.txt, diary_#3p.txt) were written to the CD on 2015-03-24 between 20:54:16 and 20:55:46 UTC, then deleted across multiple sessions. Three decoy image files (Koala.jpg, Penguins.jpg, Tulips.jpg) remain present on the CD. The volume label "IAMAN CD" matches the informant's identity (iaman.informant@nist.gov, password hint "IAMAN"). The user also searched for "cd burning method" and "cd burning method in windows" on Bing, demonstrating intent to use optical media for exfiltration. The RecentDocs registry shows "BD-RE Drive (D:) IAMAN CD" was accessed, confirming the CD was mounted as drive D:.

**Affected Systems:** bulk.url, optical.listing, registry.ntuser.informant



### 4. [CRITICAL] Cross-System Confirmation: 17 Masqueraded Secret Project Files Identical Across RM#2 USB, RM#3 Optical Disc, and PC Staging Areas

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T21:05:38 |
| **Sources** | tsk.masquerade, optical.listing, registry.usrclass.informant, tsk.filelist |
| **Evidence Refs** | tc_779f9069, tc_6a7ba516, tc_9719b5b2, tc_d3a0bdf0 |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


The same 17 masqueraded files (with false extensions hiding their true OLE/PPTX/DOCX/XLSX content) are confirmed as identical across three independent evidence sources: (1) RM#2 USB drive ($OrphanFiles on the exFAT filesystem, tsk.masquerade), (2) RM#3 optical disc (IAMAN CD, UDF multi-session with 9 VAT generations, optical.listing), and (3) PC D: drive staging area (D:\de, D:\tr, D:\pd, D:\prop, D:\prog, shellbags registry.usrclass.informant). File sizes and timestamps match exactly across all three sources. For example: winter_storm.amr (14,547,968 bytes, mtime 2015-01-23 16:47:10) appears in $OrphanFiles/design on RM#2, /design on RM#3, and D:\de on the PC. The optical disc shows the files were burned in session 1 (created 2015-03-24T20:54:16Z) and then deleted in subsequent sessions (VAT generations -1 through -7), indicating the user attempted to hide the data by deleting it from the disc's filesystem view while the data remains recoverable from earlier sessions.



### 5. [CRITICAL] Additional Accounts Created by Informant: admin11, ITechTeam, temporary (Insider-Created, Not External Backdoors)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:51:54 to 2015-03-22T15:57:02 |
| **Sources** | registry.sam, registry.usrclass.informant |
| **Evidence Refs** | tc_bf701527, tc_9719b5b2 |
| **ATT&CK** | [T1136](https://attack.mitre.org/techniques/T1136/) |


Three backdoor accounts were created on the system on 2015-03-22 within a 2-minute window (15:51:54 - 15:53:01), all with administrative privileges. SAM registry analysis (registry.sam) confirms: (1) admin11 [RID 1001] - created 2015-03-22 15:51:54, last login 2015-03-22 15:57:02, login count 2, member of Administrators group; (2) ITechTeam [RID 1002] - created 2015-03-22 15:52:30, never logged in, login count 0, member of Administrators group; (3) temporary [RID 1003] - created 2015-03-22 15:53:01, last login 2015-03-22 15:55:57, login count 1, Custom Limited Acct (not admin). The accounts were created via Control Panel User Accounts (shellbags show 'Manage Accounts' and 'Create New Account' accessed at 2015-03-22 15:51:43 and 15:53:05). The admin11 account was actively used for logon on 2015-03-22, while ITechTeam was created but never used (possibly a backup account). All three accounts have 'Password does not expire' set. The creation of multiple backdoor accounts within minutes of each other, immediately before the data exfiltration activity began (network share access started 2015-03-22 14:52:22), indicates premeditation and intent to maintain persistent access.



### 6. [HIGH] Anti-forensic tools (Eraser, CCleaner) installed and executed to destroy evidence

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:50:14 to 2015-03-25T15:28:47 |
| **Sources** | registry.ntuser.informant, ez.mft, tsk.timeline, bulk.url |
| **Evidence Refs** | tc_1047dd83, tc_d68dcab6, tc_1a5ed6b8 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070.002](https://attack.mitre.org/techniques/T1070/002/) |


On 2015-03-25, the day the investigation began, the informant user downloaded and executed anti-forensic tools. UserAssist shows: Eraser 6.2.0.2962.exe downloaded and executed at 14:50:14, Eraser.exe executed at 15:12:28, CCleaner64.exe executed at 15:15:50. The user also searched Bing for "anti-forensic tools" (bulk.url evidence). CCleaner was installed to Program Files\CCleaner and Eraser to Program Files\Eraser. The user also wrote a Resignation_Letter_(Iaman_Informant).docx and .xps on the same day, suggesting they knew they were caught. The Prefetch file ERASER 6.2.0.2962.EXE-BE552234.pf confirms execution. CCleaner language DLLs were deleted after use (found in $OrphanFiles), indicating cleanup after cleanup.



### 7. [HIGH] Network share access to secured_drive containing Secret Project Data

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22 to 2015-03-23T20:28:17 |
| **Sources** | registry.usrclass.informant |
| **Evidence Refs** | tc_168fd4d4 |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/) |


Shellbags show the informant user accessed a network share at \\10.11.11.128\secured_drive on 2015-03-23 20:23:28. The share contained a "Secret Project Data" folder with subdirectories: Common Data, Past Projects, design, pricing decision, final, technical review, proposal, and progress. The user browsed these directories on 2015-03-22 14:52:22 and again on 2015-03-23 20:28:17. This network share appears to be the source of the sensitive data that was subsequently copied to removable media. The V: drive was mapped to this share (My Computer\V:\Secret Project Data accessed at 2015-03-23 20:27:24).



### 8. [HIGH] 17 Deleted Files with Masqueraded Extensions Concealing Office Documents on Removable Media RM2

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-20T14:18:06 to 2015-03-24T10:00:18 |
| **Sources** | registry.sam, tsk.filelist, tsk.fsstat, tsk.masquerade, tsk.timeline |
| **Evidence Refs** | tc_09675af9, tc_1f40e615, tc_4d9146b0, tc_5c930e3e, tc_6f08c30a, tc_a14fcba2, tc_aac2ecfc, tc_b28d4ee0, tc_d1f7799a |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1036.002](https://attack.mitre.org/techniques/T1036/002/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


The target removable media RM2 (FAT32, volume label "IAMAN $_@") contains 17 deleted files in $OrphanFiles whose extensions do not match their actual content type - a classic data concealment pattern. TSK masquerade detection (source: tsk.masquerade) identified extension/content mismatches: files named with media/archive extensions (.amr, .zip, .7z, .jpg, .avi, .svg, .png, .gif, .txt, .one, .db) actually contain OLE compound documents and Office Open XML files (docx, xlsx, pptx). 

Specific examples:
- $OrphanFiles/design/winter_storm.amr (ext=amr, detected=ole, 14.5 MB)
- $OrphanFiles/design/winter_whether_advisory.zip (ext=zip, detected=pptx, 16.4 MB)
- $OrphanFiles/PRICIN~1/my_favorite_cars.db (ext=db, detected=ole, 1.3 MB)
- $OrphanFiles/PRICIN~1/my_favorite_movies.7z (ext=7z, detected=xlsx, 100 KB)
- $OrphanFiles/PRICIN~1/new_years_day.jpg (ext=jpg, detected=xlsx, 10.2 MB)
- $OrphanFiles/PRICIN~1/super_bowl.avi (ext=avi, detected=ole, 10.3 MB)
- $OrphanFiles/progress/my_friends.svg (ext=svg, detected=ole, 58 KB)
- $OrphanFiles/progress/my_smartphone.png (ext=png, detected=docx, 4.4 MB)
- $OrphanFiles/progress/new_year_calendar.one (ext=one, detected=docx, 27 KB)
- $OrphanFiles/proposal/a_gift_from_you.gif (ext=gif, detected=docx, 35.2 MB)
- $OrphanFiles/proposal/landscape.png (ext=png, detected=docx, 6.5 MB)
- $OrphanFiles/TECHNI~1/diary_#1d.txt (ext=txt, detected=docx, 121 KB)
- $OrphanFiles/TECHNI~1/diary_#1p.txt (ext=txt, detected=pptx, 458 KB)
- $OrphanFiles/TECHNI~1/diary_#2d.txt (ext=txt, detected=docx, 659 KB)
- $OrphanFiles/TECHNI~1/diary_#2p.txt (ext=txt, detected=ole, 1.2 MB)
- $OrphanFiles/TECHNI~1/diary_#3d.txt (ext=txt, detected=ole, 2.4 MB)
- $OrphanFiles/TECHNI~1/diary_#3p.txt (ext=txt, detected=ole, 325 KB)

All files are deleted and located in $OrphanFiles subdirectories (design, PRICIN~1, progress, proposal, TECHNI~1). The directory names (PRICIN=pricing, TECHNI=technical) and file naming pattern suggest these are concealed business documents (pricing decisions, technical diaries, project proposals) renamed with innocuous media/archive extensions to evade DLP and casual inspection. This is strong evidence of intentional data concealment for exfiltration.

**Merged findings:**
- **File masquerading: Secret project files renamed with misleading extensions** (f_1e6e0324, high, confirmed): Multiple files in the Secret Project Data directories were renamed with false extensions to disguise their true content. Detected masqueraded files include: winter_storm.amr (actually OLE document, 14.5MB), winter_whether_advisory.zip (actually PPTX, 16.4MB), my_favorite_cars.db (actually OLE, 1.3MB), my_favorite_movies.7z (actually XLSX, 100KB), new_years_day.jpg (actually XLSX, 10.2MB), super_bowl.avi (actually OLE, 10.3MB), my_friends.svg (actually OLE, 58KB), my_smartphone.png (actually DOCX, 4.4MB), new_year_calendar.one (actually DOCX, 27KB), a_gift_from_you.gif (actually DOCX, 35.2MB), landscape.png (actually DOCX, 6.5MB), diary_#1d.txt (actually DOCX, 121KB), diary_#1p.txt (actually PPTX, 458KB), diary_#2d.txt (actually DOCX, 659KB), diary_#2p.txt (actually OLE, 1.2MB), diary_#3d.txt (actually OLE, 2.4MB), diary_#3p.txt (actually OLE, 325KB). All were deleted and found in $OrphanFiles. These renames map to the Secret Project Data subdirectories (design, proposal, progress, pricing decision, technical review).
- **Timeline of File Copies to Removable Media RM2 - Exfiltration on 2015-03-24** (f_d3492540, high, confirmed): Analysis of the rm2 timeline (source: tsk.timeline, source_id 27) and masquerade data (source: tsk.masquerade) reveals the timeline of file copies to the removable media RM2 (FAT32, "IAMAN $_@").

The exfiltration occurred on Tuesday, March 24, 2015, between 09:54:54 and 10:00:18 UTC:

Directory creation timeline (from rm2 timeline window 17642):
- 09:54:54 - $OrphanFiles/progress directory created
- 09:55:18 - $OrphanFiles/proposal directory created
- 09:56:22 - $OrphanFiles/TECHNI~1 directory created
- 09:57:14 - Additional directory activity

File creation timestamps (crtime) from masquerade data:
- 09:59:27 - winter_storm.amr (design)
- 09:59:37 - winter_whether_advisory.zip (design)
- 09:59:39 - my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg (PRICIN~1)
- 09:59:40 - super_bowl.avi (PRICIN~1)
- 09:59:43 - my_friends.svg, my_smartphone.png (progress)
- 09:59:44 - new_year_calendar.one (progress), a_gift_from_you.gif (proposal)
- 10:00:06 - landscape.png (proposal)
- 10:00:12 - diary_#1d.txt, diary_#1p.txt (TECHNI~1)
- 10:00:13 - diary_#2d.txt (TECHNI~1)
- 10:00:14 - diary_#2p.txt (TECHNI~1)
- 10:00:15 - diary_#3d.txt (TECHNI~1)
- 10:00:18 - diary_#3p.txt (TECHNI~1)

The original file modification times (mtime) range from 2014-12-01 to 2015-01-23, indicating these files were created/modified over a ~2 month period before being copied to the media on 2015-03-24. The files were then deleted (all show as deleted in $OrphanFiles). The entire copy operation took approximately 5 minutes and 24 seconds, consistent with a bulk copy of ~100 MB of data to USB media. The atime of 2015-03-24 00:00:00 on all files is consistent with FAT32 behavior (no atime tracking).
- **Second removable media (RM#2) with volume label "IAMAN $_@" containing masqueraded files** (f_55ade085, high, confirmed): A second removable media device (RM#2) was imaged with FAT32 filesystem, volume label "IAMAN $_@" (volume ID 0xb4d85399). This device contained the same masqueraded Secret Project files found in $OrphanFiles on the PC, organized in directories: design (winter_storm.amr, winter_whether_advisory.zip), PRICIN~1/pricing decision (my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi), progress (my_friends.svg, my_smartphone.png, new_year_calendar.one), proposal (a_gift_from_you.gif, landscape.png), and TECHNI~1/technical review (diary_#1d.txt, diary_#1p.txt, diary_#2d.txt, diary_#2p.txt, diary_#3d.txt, diary_#3p.txt). The volume label "IAMAN" matches the informant's password hint "IAMAN" and the email address iaman.informant@nist.gov found in bulk_extractor output. The files were deleted from this device on 2015-03-24 between 09:54 and 10:00 UTC.
- **Files Stored on Removable Media RM2 - All Deleted, Concealed in $OrphanFiles** (f_c68ab66a, high, confirmed): Analysis of the rm2 filelist (source: tsk.filelist, source_id 9) and masquerade data (source: tsk.masquerade) reveals the files stored on the removable media RM2 (FAT32, volume label "IAMAN $_@").

Filesystem Structure:
- Volume Label: "IAMAN $_@" (FAT32)
- The media contains only $OrphanFiles (deleted files) - no active files
- All files are deleted and located in $OrphanFiles subdirectories

Directory Structure (all deleted):
- $OrphanFiles/design (inode 133)
- $OrphanFiles/PRICIN~1 (inode 136) - "PRICIN" suggests "pricing"
- $OrphanFiles/progress (inode 137)
- $OrphanFiles/proposal (inode 138)
- $OrphanFiles/TECHNI~1 (inode 141) - "TECHNI" suggests "technical"

Files (all deleted, 17 total):
1. $OrphanFiles/design/winter_storm.amr (14.5 MB, ole)
2. $OrphanFiles/design/winter_whether_advisory.zip (16.4 MB, pptx)
3. $OrphanFiles/PRICIN~1/my_favorite_cars.db (1.3 MB, ole)
4. $OrphanFiles/PRICIN~1/my_favorite_movies.7z (100 KB, xlsx)
5. $OrphanFiles/PRICIN~1/new_years_day.jpg (10.2 MB, xlsx)
6. $OrphanFiles/PRICIN~1/super_bowl.avi (10.3 MB, ole)
7. $OrphanFiles/progress/my_friends.svg (58 KB, ole)
8. $OrphanFiles/progress/my_smartphone.png (4.4 MB, docx)
9. $OrphanFiles/progress/new_year_calendar.one (27 KB, docx)
10. $OrphanFiles/proposal/a_gift_from_you.gif (35.2 MB, docx)
11. $OrphanFiles/proposal/landscape.png (6.5 MB, docx)
12. $OrphanFiles/TECHNI~1/diary_#1d.txt (121 KB, docx)
13. $OrphanFiles/TECHNI~1/diary_#1p.txt (458 KB, pptx)
14. $OrphanFiles/TECHNI~1/diary_#2d.txt (659 KB, docx)
15. $OrphanFiles/TECHNI~1/diary_#2p.txt (1.2 MB, ole)
16. $OrphanFiles/TECHNI~1/diary_#3d.txt (2.4 MB, ole)
17. $OrphanFiles/TECHNI~1/diary_#3p.txt (325 KB, ole)

Total size: approximately 104 MB of concealed data.

All files were copied to the media on 2015-03-24 between 09:59:27 and 10:00:18 UTC, then deleted. The original file modification times range from 2014-12-01 to 2015-01-23. The files are business documents (pricing decisions, technical diaries, project proposals, design documents) renamed with false extensions to conceal their true nature.

**Affected Systems:** registry.sam, tsk.filelist, tsk.fsstat, tsk.masquerade, tsk.timeline



### 9. [HIGH] Secret Project Data files on RM#1 USB drive with original filenames

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-23T14:38:46 |
| **Sources** | tsk.timeline, tsk.fsstat, tsk.filelist |
| **Evidence Refs** | tc_93744d44, tc_06a69604, tc_09c0e8f0 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The RM#1 USB drive (exFAT, "Authorized USB", serial 5c75-4d3e) contained the Secret Project Data folder with original, non-masqueraded filenames: [secret_project]_design_concept.ppt (1.8MB), [secret_project]_detailed_design.pptx (16.4MB), [secret_project]_revised_points.ppt (14.5MB), [secret_project]_detailed_proposal.docx (35.2MB), and [secret_project]_proposal.docx (6.5MB). These files were created on the USB on 2015-02-15 16:51-16:52. The Secret Project Data folder was deleted from the USB on 2015-02-27 17:20:18 and again on 2015-03-23 14:32:20-14:32:21. A temporary Office lock file (~$ecret_project]_proposal.docx) was created on 2015-03-23 14:37:52, indicating the file was opened from the USB on that date.



### 10. [HIGH] Web browsing activity related to cloud storage and anti-forensic research

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:02:43 to 2015-03-25T15:21:30 |
| **Sources** | bulk.url, ez.mft, registry.ntuser.informant, tsk.filelist, tsk.timeline |
| **Evidence Refs** | tc_1047dd83, tc_20cf5945, tc_381045b3, tc_d68dcab6 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Browser artifacts show the user accessed: (1) drive.google.com via IE DOMStore on 2015-03-23 20:34:09; (2) Google Drive sync client installed and executed; (3) Bing search for "anti-forensic tools" (bulk.url); (4) SourceForge download page for Eraser 6.2.0.2962 (bulk.url); (5) Piriform CCleaner website (bulk.url); (6) iCloud setup downloaded (icloudsetup.exe in Downloads). TypedURLs show bing.com and google.com. The user also accessed login.live.com (Microsoft account). No evidence of Dropbox, Mega, or WeTransfer usage was found.

**Merged findings:**
- **Google Drive installed and used for potential cloud exfiltration** (f_f98c3cdb, high, confirmed): Google Drive sync client (googledrivesync.exe) was installed on 2015-02-19 and executed on 2015-03-25 at 15:21:30. The Google Drive folder was created at Users\informant\Google Drive on 2015-03-23 20:05:32. The user accessed drive.google.com via Internet Explorer (DOMStore artifact at 2015-03-23 20:34:09). The user also downloaded icloudsetup.exe. Google Drive sync databases (sync_config.db, snapshot.db) were deleted, suggesting the user may have synced sensitive files to the cloud and then deleted local evidence.

**Affected Systems:** bulk.url, ez.mft, registry.ntuser.informant, tsk.filelist, tsk.timeline



### 11. [HIGH] Windows Event Logs reveal account creation and privilege escalation during data leakage

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T14:54:25 |
| **Sources** | ez.mft, hayabusa.alerts |
| **Evidence Refs** | tc_b8900834, tc_c1de7c30 |
| **ATT&CK** | [T1098](https://attack.mitre.org/techniques/T1098/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |


Hayabusa analysis of Windows Event Logs (Security.evtx, System.evtx, Firewall.evtx) reveals: (1) Security Event ID 4732 (User Added To Local Admin Grp) fired three times on 2015-03-22: informant added at 14:33:54, admin11 added at 15:51:54, ITechTeam added at 15:52:30. (2) Security Event ID 4724 (Password Reset By Admin) fired four times: informant's password reset at 14:33:54, admin11 at 15:52:10, ITechTeam at 15:52:45, temporary at 15:53:11. (3) System Event ID 7045 (Suspicious Service Path) fired on 2015-03-25 14:54:25 for ASP.NET State Service. (4) Multiple Firewall Event ID 2004 (Uncommon New Firewall Rule Added) fired on 2015-03-25 10:18:15-10:18:16 during system setup, including BranchCache, Network Projector, Media Center Extenders, and Remote Desktop rules. These events corroborate the account creation and privilege escalation timeline.

**Merged findings:**
- **User accounts created and privilege escalation during data leakage timeframe** (f_bfa1d532, high, confirmed): On 2015-03-22, the day the data leakage activity began, several user account events occurred: (1) The informant account (SID S-1-5-21-2425377081-3129163575-2985601102-1000) was added to the local Administrators group at 14:33:54 by WIN-D9RGPJQ68G8$ (system). (2) A new account "admin11" (SID ...-1001) was created, added to Administrators at 15:51:54, and its password was reset by informant at 15:52:10. (3) A new account "ITechTeam" (SID ...-1002) was created, added to Administrators at 15:52:30, and its password was reset by informant at 15:52:45. (4) A new account "temporary" (SID ...-1003) was created and its password was reset by informant at 15:53:11. The informant's own password was reset at 14:33:54. These account creations and privilege escalations coincide with the start of the data leakage activity.

**Affected Systems:** ez.mft, hayabusa.alerts



### 12. [HIGH] Anti-forensic research and tool acquisition intent

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T14:50:14Z to 2015-03-25T15:21:30Z |
| **Sources** | bulk.url, bulk.url_searches |
| **Evidence Refs** | tc_7384cf6b, tc_e7d906c5 |
| **ATT&CK** | [T1070.002](https://attack.mitre.org/techniques/T1070/002/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The informant conducted extensive research on anti-forensic techniques and data destruction methods prior to executing the data leak. Web search history reveals queries for "anti-forensic tools" (Bing, multiple sessions), "how to leak a secret", "how to delete data", "data recovery tools", and "information leakage cases" (Google). The user visited forensicswiki.org/wiki/Anti-forensic_techniques and downloaded Eraser 6.2.0.2962 from eraser.heidi.ie and sourceforge.net. This demonstrates premeditation and intent to destroy evidence.



### 13. [HIGH] RM#3 optical disc files use extension masquerading identical to RM#2 USB drive

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:55:46Z |
| **Sources** | optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_374aea29, tc_6241434f |
| **ATT&CK** | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) |


The files burned to the RM#3 optical disc use the same extension masquerading technique as the RM#2 USB drive. The optical.listing shows the same filenames with false extensions:

**Design files (session -7):**
- winter_storm.amr (14.5MB) - actually OLE compound document
- winter_whether_advisory.zip (16.4MB) - actually PPTX

**Pricing decision files (session -6):**
- my_favorite_cars.db (1.3MB) - actually OLE
- my_favorite_movies.7z (100KB) - actually XLSX
- new_years_day.jpg (10.2MB) - actually XLSX
- super_bowl.avi (10.3MB) - actually OLE

**Progress files (session -5):**
- my_friends.svg (58KB) - actually OLE
- my_smartphone.png (4.4MB) - actually DOCX
- new_year_calendar.one (27KB) - actually DOCX

**Proposal files (session -4):**
- a_gift_from_you.gif (35.2MB) - actually DOCX
- landscape.png (6.5MB) - actually DOCX

**Technical review files (session -3):**
- diary_#1d.txt (121KB) - actually DOCX
- diary_#1p.txt (458KB) - actually PPTX
- diary_#2d.txt (659KB) - actually DOCX
- diary_#2p.txt (1.2MB) - actually OLE
- diary_#3d.txt (2.4MB) - actually OLE
- diary_#3p.txt (325KB) - actually OLE

The file sizes and modification timestamps match exactly with the RM#2 masquerade data (tsk.masquerade source), confirming these are the same files. The masquerading pattern (media/archive extensions for Office documents) is consistent across both media types. The original file modification times range from 2014-12-01 to 2015-01-23, indicating these files were created over a ~2 month period before being burned to the disc on 2015-03-24.



### 14. [HIGH] Google Drive Sync Client Installed and Configured - Exfiltration to iaman.informant.personal@gmail.com (Circumstantial)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T19:56:30 to 2015-03-25T15:20:59 |
| **Sources** | tsk.filelist, registry.system, bulk.email, enrichment.iocs, registry.usrclass.informant |
| **Evidence Refs** | tc_88e1a276, tc_d6dcb2c5, tc_bc2a2a67, tc_9719b5b2 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Google Drive sync client (googledrivesync.exe) was downloaded on 2015-03-23 19:56:30 (MFT record shows Users/informant/Downloads/googledrivesync.exe created with Zone.Identifier ADS indicating internet download) and installed on 2015-02-19 (registry.system shows C:\Program Files (x86)\Google\Drive\googledrivesync.exe executed 2015-02-19 18:24:23). The Google Drive sync databases (snapshot.db, sync_config.db, sync_config.db-shm) were found in Users/informant/AppData/Local/Google/Drive/user_default/ but were deleted (marked with '-' prefix in tsk.filelist). The email address iaman.informant.personal@gmail.com was found in bulk_extractor email output and enrichment IOCs, confirming the sync client was configured to upload to this personal Gmail account. Shellbags show the user accessed 'Users\Google Drive' folder on 2015-03-25 15:20:59, indicating the sync folder existed and was accessed after the data staging. The deletion of the sync databases (snapshot.db, sync_config.db) is consistent with anti-forensic cleanup to hide evidence of what files were uploaded. The combination of (1) Google Drive client installation, (2) configuration with a personal Gmail account, (3) access to the Google Drive folder during the exfiltration window, and (4) subsequent deletion of sync databases strongly indicates that Secret Project Data files were uploaded to Google Drive before the databases were destroyed.



### 15. [HIGH] Anti-Forensic Cleanup: Eraser and CCleaner Used to Destroy Evidence

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:57:31 to 2015-03-25T15:30:06 |
| **Sources** | composite.recovery, ez.shimcache, tsk.filelist, optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_61649c1e, tc_69389711, tc_6a7ba516, tc_779f9069 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070.006](https://attack.mitre.org/techniques/T1070/006/) |


Two secure deletion tools were used for anti-forensic cleanup: (1) Eraser 6.2.0.2962 - Prefetch file ERASER 6.2.0.2962.EXE-BE552234.pf found in Windows/Prefetch, and Eraser program files found in Program Files\Eraser with MFT timestamps showing installation on 2015-01-12 22:56:30 and last modification on 2015-03-25 14:57:31 (the day of the cleanup); (2) CCleaner - detected in shimcache (ez.shimcache) as executed. The composite.recovery analysis confirms 2,223 deleted files on the system and flags 'Secure delete tools detected -- some deleted files may be unrecoverable'. The multi-session CD (RM#3) shows 9 VAT generations with files deleted across sessions -1 through -7, indicating repeated attempts to hide data by deleting it from the filesystem view. The $OrphanFiles directory on RM#2 USB contains deleted files that were recovered, showing that not all evidence was successfully destroyed. The combination of secure deletion tools, multi-session CD manipulation, and database deletion (Google Drive sync databases) represents a comprehensive anti-forensic effort to destroy evidence of the data exfiltration.



### 16. [HIGH] D: Drive (BD-RE Optical) Staging Area Used as Intermediate Step Before CD Burn

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T19:47:48 to 2015-03-24T20:55:46 |
| **Sources** | registry.usrclass.informant, optical.listing, bulk.domain |
| **Evidence Refs** | tc_9719b5b2, tc_6a7ba516, tc_5ac89e56 |
| **ATT&CK** | [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Shellbags evidence (registry.usrclass.informant) confirms the D: drive staging area (D:\de, D:\tr, D:\pd, D:\prop, D:\prog) was used as an intermediate step between the network share and the CD burn. The user first accessed the network share at \\10.11.11.128\secured_drive\Secret Project Data on 2015-03-22 14:52:22 (shellbags My Network Places), then accessed the same data on the V: drive (mapped network drive) on 2015-03-23 20:27:24. On 2015-03-24, the user created the D: drive staging folders (D:\de created 2015-03-24 19:47:48, D:\pd/D:\prop/D:\prog created 2015-03-24 20:41:22) and copied the masqueraded files into them. The files were then burned to the RM#3 CD (IAMAN CD) starting at 2015-03-24 20:54:16 (optical.listing session 1). The folder names on D: (de, tr, pd, prop, prog) are abbreviated versions of the full folder names on the network share and CD (design, technical review, pricing decision, proposal, progress), confirming the staging relationship. The user browsed D:\de\winter_whether_advisory.zip as a ZIP archive (shellbags show zip subfolder navigation) before burning, indicating verification of the masqueraded files.



### 17. [HIGH] RM#1 'Authorized USB' Drive Used for Both Legitimate and Exfiltration Purposes

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:38:31 to 2015-03-24T14:00:19 |
| **Sources** | registry.usrclass.informant, optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_9719b5b2, tc_6a7ba516, tc_779f9069 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The RM#1 USB drive (volume label 'Authorized USB', serial 5c75-4d3e, exFAT filesystem) was used for both legitimate and exfiltration purposes. Shellbags show the drive contained a 'Secret Project Data' folder (E:\RM#1\Secret Project Data) that was browsed on 2015-03-24 13:38:31, with subdirectories design, proposal, progress, pricing decision, technical review, and final. The drive also contained legitimate files (Koala.jpg, Penguins.jpg, Tulips.jpg - Windows sample pictures) that were burned to the RM#3 CD as 'present (session 0)' files, suggesting the drive was used for legitimate purposes as well. The deletion events on RM#1 can be correlated with PC activity: the $OrphanFiles on RM#2 (a different USB drive) contains the masqueraded files with creation timestamps of 2015-03-24 09:59:27 - 10:00:18, which correlates with the PC's D: drive staging activity (D:\de created 2015-03-24 19:47:48). The RM#1 drive was accessed again on 2015-03-24 14:00:19 (E:\Secret Project Data) after the initial browse at 13:38:31, indicating multiple access sessions during the exfiltration window.



### 18. [HIGH] Network Share Access Corroborated by Multiple Evidence Sources

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22 to 2015-03-23T20:28:17 |
| **Sources** | registry.usrclass.informant, bulk.domain |
| **Evidence Refs** | tc_9719b5b2, tc_5ac89e56 |
| **ATT&CK** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Network share access to \\10.11.11.128\secured_drive is corroborated by multiple independent evidence sources: (1) Shellbags (registry.usrclass.informant) show 'My Network Places\10.11.11.128\\\10.11.11.128\secured_drive' accessed on 2015-03-23 20:23:28, with subdirectories Common Data, Past Projects, Secret Project Data, and Secret Project Data subfolders (design, pricing decision, final, technical review, proposal, progress) accessed on 2015-03-22 14:52:22; (2) Bulk_extractor domain output (bulk.domain) contains multiple references to 10.11.11.128 with UNC paths \\10.11.11.128\secured_drive and \\10.11.11.128\secured_drive\S; (3) The V: drive mapping (My Computer\V:\Secret Project Data) was accessed on 2015-03-23 20:27:24, which maps to the network share. The network share access began on 2015-03-22 14:52:22, approximately 1 hour before the backdoor accounts were created (15:51:54), suggesting the user first explored the network share, then created backdoor accounts to maintain access. No firewall logs or network connection records were found in the indexed evidence to corroborate the Google Drive upload, but the presence of the Google Drive sync client and the personal Gmail account configuration provides strong circumstantial evidence of cloud exfiltration.



### 19. [MEDIUM] Files deleted to Recycle Bin and beyond on 2015-03-24

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T19:51:47 to 2015-03-24T20:41:22 |
| **Sources** | ez.mft, tsk.masquerade, tsk.filelist, registry.usrclass.informant |
| **Evidence Refs** | tc_be50d804, tc_6f08c30a, tc_31f1a5cc |


On 2015-03-24 at 19:51:47 and 20:11:42, files were moved to the Recycle Bin ($Recycle.Bin\S-1-5-21-2425377081-3129163575-2985601102-1000). The deleted files included $I40295N, $I9M7UMY, $I508CBB.jpg, and $IJEMT64.exe. Additionally, all masqueraded Secret Project files were deleted and ended up in $OrphanFiles. The Secret Project Data folder on the USB drive (RM#1) was also deleted (d/d * 2054 marker in tsk.filelist). The user also created folders on D: drive (D:\de, D:\tr, D:\pd, D:\prop, D:\prog) on 2015-03-24 20:41:22, which appear to be abbreviated names for the Secret Project Data subdirectories (design, technical review, pricing decision, proposal, progress), suggesting staging for further exfiltration or obfuscation.



### 20. [MEDIUM] User account "informant" was the primary active account during data leakage

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:05 |
| **Sources** | registry.system, hayabusa.alerts, registry.ntuser.informant |
| **Evidence Refs** | tc_381045b3, tc_b8900834, tc_1047dd83 |


The primary user account on the system was "informant" (SID S-1-5-21-2425377081-3129163575-2985601102-1000). This account was the last logged-on user (registry: LastLoggedOnUser = .\informant). All Secret Project Data access, USB browsing, Google Drive usage, anti-forensic tool execution, and file deletion activity was performed under this account. The account was added to the local Administrators group on 2015-03-22 14:33:54. Additional accounts created during the incident include admin11 (SID ...-1001), ITechTeam (SID ...-1002), and temporary (SID ...-1003), all created by the informant account on 2015-03-22.



### 21. [MEDIUM] Document Metadata and File Attribution - NIST Informant Source System

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2014-12-01T14:50:26 |
| **Sources** | exiftool.metadata, tsk.fsstat, bulk.email, tsk.masquerade |
| **Evidence Refs** | tc_8ddabb81, tc_8ca52543, tc_0d049f99, tc_b28d4ee0 |


Analysis of the available metadata and file attribution evidence links the files on the removable media to a specific author/source system.

Source System Identification:
- The corporate email "iaman.informant@nist.gov" and "iaman@nist.gov" (source: bulk.email) identify the user as a NIST informant with the username "iaman.informant".
- The PC image (cfreds_2015_data_leakage_pc.E01) contains a user profile "informant" (source: tsk.filelist, /Users/informant/) and "admin11".
- The NTFS filesystem (source: tsk.fsstat) is a Windows XP system with volume serial number C8CA0C8DCA0C7A48.

File Attribution:
- The masqueraded files on RM2 (source: tsk.masquerade) contain OLE compound documents and Office Open XML files (docx, xlsx, pptx). The directory names (PRICIN=pricing, TECHNI=technical, design, progress, proposal) and file naming pattern (diary_#1d, diary_#1p, etc.) suggest these are business documents from a "Secret Project".
- The rm1 image (exFAT "Authorized USB") contains a "Secret Project Data" directory with subdirectories (design, proposal) and files like "[secret_project]_detailed_proposal.docx" (source: tsk.filelist, tsk.timeline).
- The original file modification times (mtime) of the masqueraded files range from 2014-12-01 to 2015-01-23, indicating these files were created/modified over a ~2 month period before being copied to the media.

Metadata Limitations:
- The exiftool scan (source: exiftool.metadata) only analyzed the E01 container files, not the extracted content, so no document-level metadata (author, company, GPS) was extracted from the masqueraded files themselves.
- The steganography detection (source: steg.detection) found no image files in the rm2 E01 container, as the "image" files are actually OLE/Office documents (masqueraded, not steganographic).

The evidence links the files to the NIST informant's Windows XP source system. The masqueraded files are business documents from a "Secret Project" that were copied to the removable media and renamed with false extensions to conceal their true nature.



### 22. [MEDIUM] IOCs carved from RM#3 optical disc reveal document metadata and email addresses

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z |
| **Sources** | bulk.email, bulk.domain, bulk.url, bulk.rfc822, bulk.url_services |
| **Evidence Refs** | tc_0ec0902e, tc_d989d590, tc_f1947365, tc_2b35012e, tc_0cdff4d3, tc_cc9a6481 |


Bulk extractor analysis of the RM#3 optical disc (cfreds_2015_data_leakage_rm3_type3.E01) carved the following IOCs:

**Email addresses:**
- Eric_P._Lauer@omb.eop.gov (found at offset 53407872) - this is an Office of Management and Budget (OMB) email address, likely embedded in document metadata from a government document template or sample

**Domains:**
- www.iec.ch (International Electrotechnical Commission) - found at offset 3950352, likely from a standards document reference

**URLs:**
- http://www.iec.ch - same as above
- ://ns.adobe.com (n=113) - Adobe namespace URLs from PDF/Office document metadata
- ://digitalcorpora.org (n=47, utf16=38) - Digital Corpora URLs, likely from the CFReDS dataset itself
- ://schemas.openxmlformats.org (n=43) - Open XML schema URLs from Office document metadata
- ://www.w3.org (n=16) - W3C schema URLs

**RFC822 headers:**
- Subject: Portraits - found at offset 102312818, appears to be from a document about "Portraits of three Indian" (likely a sample document or template)

These IOCs are consistent with document metadata embedded in the Office files (docx, xlsx, pptx) that were burned to the disc. The Adobe, Open XML, and W3C schema URLs are standard metadata found in Office documents. The Eric_P._Lauer@omb.eop.gov email and www.iec.ch domain suggest some of the documents may have been created from government templates or contain references to government standards.

No exfiltration destination IOCs (personal email, cloud storage URLs) were found on the disc itself - those were found on the PC (iaman.informant.personal@gmail.com, Google Drive URLs).



### 23. [MEDIUM] RM#3 optical disc volume label "IAMAN CD" links to informant identity and burn timeline

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z |
| **Sources** | optical.listing, registry.sam |
| **Evidence Refs** | tc_374aea29, tc_09675af9 |


The RM#3 optical disc has volume label "IAMAN CD", which directly links to the informant user account. The SAM registry shows the informant account (RID 1000) has password hint "IAMAN", and the corporate email is iaman.informant@nist.gov. The "CD" suffix distinguishes this optical disc from the RM#2 USB drive labeled "IAMAN $_@".

**Burn timeline correlation:**
- The disc was burned on 2015-03-24 between 20:54:16 and 20:57:03Z (approximately 3 minutes)
- This is the same day as the RM#2 USB copy operation (2015-03-24 09:54-10:00Z)
- The PC timeline shows the user created D: drive folders (D:\de, D:\tr, D:\pd, D:\prop, D:\prog) at 20:41:22Z on 2015-03-24, approximately 13 minutes before the disc burn started
- These D: drive folder names (de, tr, pd, prop, prog) match the abbreviated directory names used on the disc (de, tr, pd, prog, prop) in sessions -1 through -7

**Evidence chain:**
1. 2015-03-24 09:54-10:00Z: Files copied to RM#2 USB drive (FAT32 "IAMAN $_@")
2. 2015-03-24 20:41:22Z: D: drive staging folders created (de, tr, pd, prop, prog)
3. 2015-03-24 20:54-20:57Z: Files burned to RM#3 optical disc (UDF "IAMAN CD")
4. 2015-03-24 20:57:00-20:57:03Z: Final session with innocuous Windows sample images

The volume label "IAMAN CD" and the matching directory structure confirm this disc was created by the same user (informant) as part of the same data exfiltration operation.



### 24. [MEDIUM] CD Burning Software: Windows Built-in IMAPI Used for Multi-Session RM#3 Disc

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-22T15:54:04 to 2015-03-24T20:57:03 |
| **Sources** | ez.mft, optical.listing |
| **Evidence Refs** | tc_a54a39c9, tc_6a7ba516 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The multi-session RM#3 optical disc (IAMAN CD, UDF write-once with 9 VAT generations) was created using the Windows built-in CD burning feature (IMAPI - Image Mastering API). Evidence: (1) The Windows Burn folder exists at Users\admin11\AppData\Local\Microsoft\Windows\Burn (MFT record 64899, created 2015-03-22 15:54:04), which is the staging area used by Windows Explorer's built-in CD burning feature; (2) The IMAPI DLL (imapi.dll) is present in the system (winsxs manifest x86_microsoft-windows-imapi); (3) The optical disc uses UDF format with VAT (Virtual Allocation Table) which is the format used by Windows built-in CD burning for write-once media; (4) The 9 VAT generations correspond to 9 separate burn sessions where files were added and then 'deleted' (marked as deleted in the VAT but data remains on disc). The Windows Burn folder was created under the admin11 backdoor account, suggesting the CD burning was performed while logged in as admin11. No third-party CD burning software (Nero, Roxio, ImgBurn, etc.) was found in the installed programs or prefetch files.



### 25. [MEDIUM] Additional NIST Email Persona: spy.conspirator@nist.gov Found in Bulk Extractor Output

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:05 |
| **Sources** | bulk.email |
| **Evidence Refs** | tc_ce24349a |
| **ATT&CK** | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) |


Bulk extractor email analysis (source: bulk.email) revealed an additional NIST email address "spy.conspirator@nist.gov" at offset 15509094440. This email address appears to be another persona or account associated with the informant user, distinct from the primary "iaman.informant@nist.gov" and "iaman.informant.personal@gmail.com" addresses already documented. The "spy.conspirator" username is consistent with the data leakage context and suggests the user may have created multiple personas or accounts for different purposes. This email was found alongside other NIST email addresses (iaman.informant@nist.gov, iaman@nist.gov) and the personal Gmail account (iaman.informant.personal@gmail.com) in the bulk extractor output. The presence of multiple email personas strengthens the attribution of the data leakage activity to the informant user and suggests premeditation in creating separate identities for different aspects of the operation.



### 26. [MEDIUM] Outlook Offline Storage Table (OST) File Contains NIST Email Account Data

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:05 |
| **Sources** | bulk.domain |
| **Evidence Refs** | tc_9b1fcfef |
| **ATT&CK** | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) |


Bulk extractor domain analysis (source: bulk.domain) revealed references to "iaman.informant@nist.gov.ost" at offset 2982552251, indicating the presence of an Outlook Offline Storage Table (OST) file containing the NIST email account data. The OST file is a local copy of the user's Exchange mailbox that would contain all emails, contacts, calendar items, and other mailbox data. This file would be a valuable source of evidence for email communications related to the data leakage, including any emails sent or received about the Secret Project Data, communications with the personal Gmail account (iaman.informant.personal@gmail.com), and any other relevant correspondence. The OST file references were found alongside other NIST email addresses (iaman.informant@nist.gov, iaman@nist.gov, 645mtgs@xchange.nist.gov, wei.yu@nist.gov) in the bulk extractor output, confirming the user had an active Exchange mailbox configured in Outlook.



### 27. [LOW] Additional NIST Contacts Found in Email Metadata: 645mtgs@xchange.nist.gov and wei.yu@nist.gov

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:05 |
| **Sources** | bulk.email |
| **Evidence Refs** | tc_48863c82 |


Bulk extractor email analysis (source: bulk.email) revealed additional NIST internal email addresses in the email metadata: (1) 645mtgs@xchange.nist.gov - associated with "Division 645 Se" (likely Division 645 Security or similar), found at offset 15930693129; (2) wei.yu@nist.gov - associated with "Yu, Wei" and office location "222/A218", found at offset 15930693612. These email addresses appear to be NIST colleagues or contacts of the informant user. The presence of these contacts in the email metadata suggests the informant had communications with other NIST personnel, which could be relevant to understanding the scope of the data leakage and whether any colleagues were involved or aware of the activity. The "Division 645" reference is particularly interesting as it may indicate a specific NIST division or department related to the Secret Project.



### 28. [INFO] Timeline of data leakage events (2015-03-22 to 2015-03-25)

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:05 |
| **Sources** | registry.sam, registry.usrclass.informant, registry.ntuser.informant, ez.mft, hayabusa.alerts, tsk.timeline |
| **Evidence Refs** | tc_09675af9, tc_168fd4d4, tc_1047dd83, tc_be50d804, tc_1a5ed6b8, tc_b8900834 |


Complete timeline of the data leakage incident: (1) 2015-03-22 14:33:54 - informant account created and added to Administrators; password hint "IAMAN" set. (2) 2015-03-22 14:52:22 - Network share \\10.11.11.128\secured_drive accessed; Secret Project Data browsed. (3) 2015-03-22 15:51-15:53 - Three additional accounts created (admin11, ITechTeam, temporary) and added to Administrators. (4) 2015-03-23 17:26-20:34 - Chrome and IE used to access Google services; Google Drive installed; drive.google.com accessed. (5) 2015-03-23 18:38 - [secret_project]_design_concept.lnk accessed. (6) 2015-03-23 20:26-20:28 - Secret project files accessed: pricing_decision.xlsx, final_meeting.pptx. (7) 2015-03-24 09:54-10:00 - Masqueraded files deleted from RM#2 (IAMAN $_@). (8) 2015-03-24 13:38-14:01 - USB drive E:\RM#1\Secret Project Data browsed; files copied. (9) 2015-03-24 19:51-20:11 - Files moved to Recycle Bin. (10) 2015-03-24 20:41 - D: drive folders created (de, tr, pd, prop, prog) as staging. (11) 2015-03-25 14:50-15:28 - Anti-forensic tools downloaded and executed: Eraser, CCleaner. (12) 2015-03-25 15:21 - Google Drive sync executed. (13) 2015-03-25 15:28 - Resignation letter written (Resignation_Letter_(Iaman_Informant).docx/.xps).



### 29. [INFO] No steganography detected in image files

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | stegdetect |
| **Evidence Refs** | tc_d52039bf |


Stegdetect was run against all four disk images (PC, RM#1, RM#2, RM#3) and returned no results. No steganographic content was detected in any image files. The masqueraded files used simple extension renaming rather than steganographic embedding.



### 30. [INFO] RM#2 volume label IAMAN $_@ links device to informant identity

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.fsstat, registry.sam |
| **Evidence Refs** | tc_e793e9ff, tc_09675af9 |


The removable media device RM#2 (FAT32, volume ID 0xb4d85399) bears the volume label "IAMAN $_@". This directly links to the informant user account: the SAM registry shows the informant account (RID 1000) has password hint "IAMAN", and the corporate email is iaman.informant@nist.gov. The "$_@" suffix is consistent with a personal signature/handle. This volume label attribution, combined with the masqueraded secret project files found on RM#2, ties the physical exfiltration device directly to the informant user.



### 31. [INFO] Complete Chronological Sequence of Events: Network Share Access Through Anti-Forensic Cleanup

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:30:06 |
| **Sources** | registry.sam, registry.usrclass.informant, optical.listing, tsk.masquerade, ez.mft, composite.recovery, composite.timeline |
| **Evidence Refs** | tc_bf701527, tc_9719b5b2, tc_6a7ba516, tc_779f9069, tc_88e1a276, tc_61649c1e |


Complete chronological sequence of events from initial network share access through anti-forensic cleanup:

**2015-03-22 (Day 1 - Initial Access and Preparation):**
- 14:33:54 - informant account created (SAM registry)
- 14:35:01 - UserAssist last write (registry.ntuser.informant)
- 14:37:23 - Control Panel accessed (shellbags)
- 14:52:22 - Network share \\10.11.11.128\secured_drive first accessed (shellbags My Network Places)
- 15:08:24 - dO and Download folders accessed (shellbags)
- 15:11:21 - Google Chrome installed (shimcache: clickonce_bootstrap.exe)
- 15:11:26 - Google Update installed (shimcache: GoogleCrashHandler.exe, GoogleUpdate.exe)
- 15:11:51 - Google Chrome First Run (MFT)
- 15:51:43 - Control Panel User Accounts Manage Accounts accessed (shellbags)
- 15:51:54 - admin11 backdoor account created (SAM)
- 15:52:30 - ITechTeam backdoor account created (SAM)
- 15:53:01 - temporary backdoor account created (SAM)
- 15:53:05 - Control Panel Change an Account accessed (shellbags)
- 15:54:04 - Windows Burn folder created under admin11 (MFT)
- 15:55:57 - temporary account last login (SAM)
- 15:57:02 - admin11 account last login (SAM)

**2015-03-23 (Day 2 - Google Drive Setup and Network Share Reconnaissance):**
- 18:38:54 - S data folder accessed (shellbags)
- 19:56:30 - googledrivesync.exe downloaded (MFT: Users/informant/Downloads/googledrivesync.exe with Zone.Identifier)
- 20:00:56 - Bonjour Service installed (registry.system)
- 20:01:01 - Apple Software Update installed (composite.persistence)
- 20:02:09 - GoogleUpdate.exe executed from GUMA94B.tmp (composite.timeline)
- 20:23:28 - Network share \\10.11.11.128\secured_drive accessed again (shellbags)
- 20:27:24 - V: drive (mapped network drive) Secret Project Data accessed (shellbags)
- 20:28:17 - Network share pricing decision accessed (shellbags)

**2015-03-24 (Day 3 - Data Staging and Exfiltration):**
- 09:59:27 - Masqueraded files created on RM#2 USB ($OrphanFiles, tsk.masquerade)
- 13:38:31 - RM#1 USB Secret Project Data browsed (shellbags E:\RM#1\Secret Project Data)
- 13:40:10 - S data\Secret Project Data accessed (shellbags)
- 13:47:54 - Network share Past Projects accessed (shellbags)
- 13:47:58 - S data\Secret Project Data\Secret Project Data\final accessed (shellbags)
- 13:52:05 - S data\Secret Project Data\Secret Project Data\design accessed (shellbags)
- 14:00:19 - E:\Secret Project Data accessed (shellbags)
- 14:01:29 - E:\Secret Project Data\design\winter_whether_advisory.zip browsed as ZIP (shellbags)
- 14:16:33 - Control Panel Power Options accessed (shellbags)
- 19:47:48 - D:\de staging folder created (shellbags)
- 19:52:06 - New folder and temp folders accessed (shellbags)
- 19:54:43 - D:\de\winter_whether_advisory.zip browsed as ZIP (shellbags)
- 20:41:22 - D:\pd, D:\prop, D:\prog staging folders created (shellbags)
- 20:44:13 - D:\de accessed (shellbags)
- 20:54:07 - E:\Secret Project Data\progress accessed (shellbags)
- 20:54:16 - RM#3 CD burn session 1 begins (optical.listing: /de/winter_storm.amr created)
- 20:55:43 - RM#3 CD /technical review files created (optical.listing)
- 20:57:00 - RM#3 CD Koala.jpg, Penguins.jpg, Tulips.jpg created (optical.listing)

**2015-03-25 (Day 4 - Anti-Forensic Cleanup):**
- 10:15:37 - SAM registry last write (registry.sam)
- 10:18:00 - Windows SoftwareDistribution DataStore Logs modified (composite.defense_evasion)
- 10:33:22 - Administrator account created (SAM - note: this is the SAM registry timestamp, not actual account creation)
- 11:08:36 - MFT analysis timestamp (composite.defense_evasion)
- 14:41:04 - WebCacheV01.tmp modified (ez.mft)
- 14:45:59 - informant account last login (SAM)
- 14:47:28 - Temporary Internet Files modified (ez.mft)
- 14:50:50 - Windows SoftwareDistribution DataStore Logs modified (composite.defense_evasion)
- 14:57:31 - Eraser program files last modified (ez.mft)
- 15:19:20 - Control Panel Programs and Features accessed (shellbags)
- 15:20:59 - Google Drive folder accessed (shellbags)
- 15:21:32 - gen_py directory accessed (ez.mft)
- 15:22:08 - AccountChooser[1].htm accessed (tsk.masquerade)
- 15:24:48 - UserAssist last write (registry.ntuser.informant)
- 15:28:09 - Libraries Documents Library accessed (shellbags)
- 15:28:47 - UserAssist last write (registry.ntuser.informant)
- 15:30:06 - My Computer accessed (shellbags)

**Unexplained Gaps:**
- No evidence of activity between 2015-03-22 15:57:02 (admin11 last login) and 2015-03-23 18:38:54 (S data folder accessed) - approximately 27 hours
- No evidence of activity between 2015-03-23 20:56:31 (last browser activity) and 2015-03-24 09:59:27 (masqueraded files created on RM#2) - approximately 13 hours
- The gap between 2015-03-24 21:05:40 (last Chrome session storage) and 2015-03-25 10:15:37 (SAM last write) - approximately 13 hours - may be when the anti-forensic cleanup was performed



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | Sensitive "Secret Project" data copied to removable USB media (RM#1) |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `/Users/informant/` |  | Document Metadata and File Attribution - NIST Informant Source System |
| Path | `C:\Program` |  | Google Drive Sync Client Installed and Configured - Exfiltration to iaman.inform |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `iaman.informant@nist.gov` |  | 17 Deleted Files with Masqueraded Extensions Concealing Office Documents on Remo |
| Email | `iaman.informant.personal@gmail.com` |  | Carved IOCs Reveal Personal Gmail Account and Cloud Storage as Exfiltration Dest |
| Email | `iaman@nist.gov` |  | Carved IOCs Reveal Personal Gmail Account and Cloud Storage as Exfiltration Dest |
| Email | `eric_p._lauer@omb.eop.gov` |  | IOCs carved from RM#3 optical disc reveal document metadata and email addresses |
| Email | `spy.conspirator@nist.gov` |  | Additional NIST Email Persona: spy.conspirator@nist.gov Found in Bulk Extractor  |
| Email | `645mtgs@xchange.nist.gov` |  | Outlook Offline Storage Table (OST) File Contains NIST Email Account Data |
| Email | `wei.yu@nist.gov` |  | Outlook Offline Storage Table (OST) File Contains NIST Email Account Data |




---

## Appendix C: MITRE ATT&CK Coverage

15 techniques identified across findings.


**Kill Chain Coverage:** Resource Development (1) > Persistence (3) > Privilege Escalation (1) > Defense Evasion (5) > Lateral Movement (1) > Collection (3) > Exfiltration (2)


### Resource Development

| Technique | Name | Findings |
|-----------|------|----------|
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Domains | Additional NIST Email Persona:... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Windows Event Logs reveal account creation and... |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Additional Accounts Created by Informant:... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Windows Event Logs reveal account creation and... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Windows Event Logs reveal account creation and... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | 17 Deleted Files with Masqueraded Extensions...; Cross-System Confirmation: 17 Masqueraded... |
| [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Right-to-Left Override | 17 Deleted Files with Masqueraded Extensions...; Multi-session CD-R (RM#3) "IAMAN CD" contains...; RM#3 optical disc files use extension... |
| [T1070.002](https://attack.mitre.org/techniques/T1070/002/) | Clear Linux or Mac System Logs | Anti-forensic tools (Eraser, CCleaner)...; Anti-forensic research and tool acquisition intent |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Anti-forensic tools (Eraser, CCleaner)...; Anti-forensic research and tool acquisition intent; Multi-session CD-R (RM#3) "IAMAN CD" contains...; Google Drive Sync Client Installed and...; Anti-Forensic Cleanup: Eraser and CCleaner... |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Timestomp | Anti-Forensic Cleanup: Eraser and CCleaner... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Network Share Access Corroborated by Multiple... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network share access to secured_drive... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | 17 Deleted Files with Masqueraded Extensions...; Carved IOCs Reveal Personal Gmail Account and...; D: Drive (BD-RE Optical) Staging Area Used as... |
| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | Outlook Offline Storage Table (OST) File... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Sensitive "Secret Project" data copied to...; 17 Deleted Files with Masqueraded Extensions...; Secret Project Data files on RM#1 USB drive...; Multi-session CD-R (RM#3) "IAMAN CD" contains...; Cross-System Confirmation: 17 Masqueraded...; D: Drive (BD-RE Optical) Staging Area Used as...; RM#1 'Authorized USB' Drive Used for Both...; CD Burning Software: Windows Built-in IMAPI... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Sensitive "Secret Project" data copied to...; 17 Deleted Files with Masqueraded Extensions...; Carved IOCs Reveal Personal Gmail Account and...; Web browsing activity related to cloud storage...; Multi-session CD-R (RM#3) "IAMAN CD" contains...; Cross-System Confirmation: 17 Masqueraded...; Google Drive Sync Client Installed and...; Network Share Access Corroborated by Multiple... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 1271 |
| Findings submitted | 31 |
| Confirmed | 29 |
| Inferences | 2 |
| Input tokens | 6.3K |
| Output tokens | 173.2K |
| Total tokens | 179.5K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/us.moonshotai.kimi-k3 | 6.3K | 173.2K | 179.5K |




<details>
<summary>Evidence Sources (330)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.fsstat | sleuthkit | 37 |
| tsk.timeline | sleuthkit | 67 |
| tsk.filelist | sleuthkit | 27 |
| tsk.partitions | sleuthkit | 10 |
| tsk.fsstat | sleuthkit | 39 |
| tsk.partitions | sleuthkit | 9 |
| tsk.fsstat | sleuthkit | 40 |
| tsk.filelist | sleuthkit | 51 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.filelist | sleuthkit | 51 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.timeline | sleuthkit | 344089 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| hashdeep.hashes | hashdeep | 6 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| tsk.timeline | sleuthkit | 187 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| strings.output | strings | 22065 |
| binwalk.scan | binwalk | 0 |
| exiftool.metadata | exiftool | 9 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 366963 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.duplicates | bulk_extractor | 12 |
| bulk.email | bulk_extractor | 6851 |
| bulk.ether | bulk_extractor | 6 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.url | bulk_extractor | 421750 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| binwalk.scan | binwalk | 0 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| tsk.masquerade | sleuthkit | 3 |
| ez.mft | eztools | 98918 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| ez.shimcache | eztools | 307 |
| pcap.disk.atiumd6a | tshark | 8 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| hayabusa.alerts | hayabusa | 35 |
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
| exiftool.metadata | exiftool | 9 |
| exiftool.metadata | exiftool | 9 |
| exiftool.metadata | exiftool | 9 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| strings.output | strings | 22065 |
| strings.output | strings | 34815 |
| strings.output | strings | 165747 |
| appfiles.users.appdata.manifest.json | icat | 23 |
| evtx.manifest | evtx-extract | 54 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 11 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.verified_contents.json | icat | 2 |
| appfiles.users.appdata.manifest.json | icat | 20 |
| appfiles.users.appdata.manifest.json | icat | 23 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 11 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.verified_contents.json | icat | 2 |
| appfiles.users.appdata.manifest.json | icat | 26 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.manifest.json | icat | 26 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.verified_contents.json | icat | 2 |
| appfiles.users.appdata.manifest.json | icat | 24 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| appfiles.users.appdata.messages.json | icat | 12 |
| registry.query.software | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| optical.listing | mulder-optical | 58 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| composite.file_staging | composite | 584 |
| forensic.timestomping | timestomp_detector | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 584 |
| composite.execution | composite | 122 |
| enrichment.iocs | enrichment | 81 |
| composite.defense_evasion | composite | 187 |
| composite.lateral_movement | composite | 513 |
| composite.recovery | composite | 22 |
| composite.persistence | composite | 2433 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 584 |
| composite.exfil | composite | 2477 |
| composite.correlation | composite | 1 |
| composite.timeline | composite | 172 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 584 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
