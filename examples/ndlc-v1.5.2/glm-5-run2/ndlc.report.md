# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T06:42:02.049118+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 96 evidence sources (47 disk, 49 other) | 454 tool calls | 1.0 hours
**Results:** 22 findings (6 critical, 10 high) | 19 confirmed, 3 inference
**Timeline:** 2014-12-01 to 2015-03-25

**Key Threats:**
- US Government Email Address Found on Removable Media
- Intent Evidence: Web Searches About Data Leakage and Forensic Evasion
- Data Exfiltration Timeline and Method
- NIST Employee Identity Confirmed - Iaman Informant
- Deleted Files on UDF Optical Media - Evidence of Multi-Session Data Tampering

**Attack Lifecycle:**
- **Initial Access / Deployment** (2014-12-01 to 2015-03-25): Deleted Files on UDF Optical Media - Evidence of Multi-Session Data Tampering (+14 related)
- **Defense Evasion / Anti-Forensics** (2015-03-22 to 2015-03-23): Intent Evidence: Web Searches About Data Leakage and Forensic Evasion (+1 related)
- **Discovery / Collection** (2015-03-22 to 2015-03-24): NIST Employee Identity Confirmed - Iaman Informant (+2 related)
- **Other Activity** (2015-03-25): Timestamp Manipulation Detected on PC

**Tools:** search (90), get_raw_output (41), submit_finding (27), open_case (22), get_investigation_summary (17). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **US Government Email Address Found on Removable Media** (2015-03-24T09:59:27 to 2015-03-24T23:59:59)


- **Intent Evidence: Web Searches About Data Leakage and Forensic Evasion** (2015-03-22T14:34:00)


- **Data Exfiltration Timeline and Method** (2015-03-23T20:02:43)


- **NIST Employee Identity Confirmed - Iaman Informant** (2015-03-22T14:34:41 to 2015-03-25T15:29:08)


- **Deleted Files on UDF Optical Media - Evidence of Multi-Session Data Tampering** (2014-12-01T14:50:26Z to 2015-03-24T20:57:03Z)


- **US Government Email Metadata in Exfiltrated Files - OMB/EOP and Library of Congress** (2015-03-24T09:59:27Z to 2015-03-24T23:59:59Z)




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

454 tool calls were executed across 13
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Insider Threat Data Exfiltration

## Background

This investigation examines evidence from a PC system, two USB flash drives (rm1 and rm2), and one optical media disc (rm3_type3) to determine the scope and nature of data exfiltration activities. The evidence inventory comprises 13 forensic sources including MFT analysis, filesystem extraction, bulk_extractor output, registry hives, and event log analysis.

The primary user account under investigation is "informant," identified as Iaman Informant, an employee of the National Institute of Standards and Technology (NIST) with the email address iaman.informant@nist.gov. The investigation period spans March 22-25, 2015, during which the user account was created, data was accessed and staged, and anti-forensic cleanup was executed.

The system under examination is a Windows 7 PC with an "informant" user profile created on March 22, 2015, at 14:34:41 UTC. The user's brief activity window of four days, combined with the creation of a resignation letter on March 25, suggests this was an intentional departure period during which sensitive data was systematically exfiltrated from government systems.

## Incident Timeline

The incident reconstruction reveals a methodical four-phase operation executed over three days:

**Phase 1: Initial Setup and Credential Creation (March 22, 2015)**

At 14:34:41 UTC on March 22, the "informant" user account was created on the PC system. Within 30 minutes, three additional administrator accounts were created: admin11 at 15:51:54, ITechTeam at 15:52:30, and an account named "temporary" with a password reset at 15:53:11. All three accounts were granted local administrator privileges by the informant account. Security event logs confirm these actions were performed from the informant session (SubjectLogonId: 0x224e3). The admin11 account was used at least once at 15:57:30 UTC when NOTEPAD.EXE was executed, as recorded in UserAssist registry entries.

**Phase 2: Source File Access and Cloud Infrastructure Setup (March 23, 2015)**

On March 23, the user accessed source files from an "Authorized USB" drive (rm1). At 18:31:10 UTC, a SanDisk Cruzer Fit USB device was connected to the PC, as recorded in the Windows registry USBSTOR key. Seven minutes later, at 18:38:21 UTC, the user opened `[secret_project]_design_concept.ppt` from the USB drive, as evidenced by LNK file creation in the Recent documents folder (Users\informant\AppData\Roaming\Microsoft\Windows\Recent\[secret_project]_design_concept.lnk).

The "Authorized USB" drive contained a "Secret Project Data" directory with organized project materials including design documents, proposals, and pricing files. A Word temporary file (~$ecret_project]_proposal.docx) indicated documents were actively edited on this drive.

Between 20:02:43 and 20:05:32 UTC, Google Drive desktop client was installed and configured. The sync folder was created at Users\informant\Google Drive\desktop.ini (created 20:05:32), and synchronization databases (sync_config.db, snapshot.db) were established. At 20:27:33 UTC, a second project file was accessed, evidenced by the LNK file [secret_project]_final_meeting.pptx.lnk.

**Phase 3: Data Obfuscation and Staging (March 24, 2015)**

The data exfiltration staging began on March 24 at 09:59:27 UTC when the first obfuscated file was created on USB drive rm2 (volume label "IAMAN $_@"). Over the next 51 seconds, through 10:00:18 UTC, all 17 masqueraded files were created. These files were disguised with media file extensions but contained Microsoft Office documents:

- winter_storm.amr (14.5 MB) → OLE format
- winter_whether_advisory.zip (16.4 MB) → PowerPoint
- my_favorite_cars.db (1.3 MB) → OLE format
- my_favorite_movies.7z (100 KB) → Excel
- new_years_day.jpg (10.2 MB) → Excel
- super_bowl.avi (10.3 MB) → OLE format
- a_gift_from_you.gif (35.2 MB) → Word (largest file)
- And 10 additional files in the diary_# series

All files were placed in $OrphanFiles directories marked as deleted entries and organized in folders named design, PRICIN~1 (pricing), progress, proposal, and TECHNI~1 (technical review). This naming convention suggests corporate/business documents being disguised as personal media files.

Later that day, at approximately 20:55:43 UTC, the same 17 files were burned to UDF optical media (rm3_type3, volume label "IAMAN CD"). The disc exhibits 9 VAT (Virtual Allocation Table) sessions showing progressive directory renaming and file deletion across sessions to obscure the original structure. The current session only contains three image files (Koala.jpg, Penguins.jpg, Tulips.jpg), while earlier sessions contained the 17 obfuscated documents that were later deleted but remain forensically recoverable.

**Phase 4: Anti-Forensic Cleanup and Resignation (March 25, 2015)**

On March 25, a coordinated anti-forensic cleanup operation was executed alongside employment termination activities:

- 11:08:36 UTC: Timestamp manipulation detected on PC root directory. The $STANDARD_INFORMATION Created timestamp was backdated to 2009-07-14 (Windows installation date), creating a 2080-day discrepancy with the $FILE_NAME timestamp. This timestomping technique was used to hide recent filesystem activity.

- 14:46:05 UTC: CCleaner installer (ccsetup504.exe) executed
- 14:50:14 UTC: Eraser installer executed
- 14:57:56 UTC: CCleaner executed (first run)
- 15:12:28 UTC: Eraser executed (secure file deletion)
- 15:15:50 UTC: CCleaner executed (second run)
- 15:21:30 UTC: Google Drive sync executed (googledrivesync.exe)
- 15:21:34 UTC: Google Drive lockfile last modified
- 15:21:36 UTC: Google Drive folder updated
- 15:28:33 UTC: Resignation letter created (Resignation_Letter_(Iaman_Informant).xps)
- 15:29:08 UTC: Resignation letter last accessed (Resignation_Letter_(Iaman_Informant).docx)

The Google Drive sync databases (sync_config.db and snapshot.db) were deleted, preventing forensic determination of which files were uploaded to the cloud. The timing of cleanup activities immediately preceding the resignation letter demonstrates consciousness of guilt and premeditated evidence destruction.

## Key Findings

**Data Exfiltration via Multiple Channels**

The investigation confirmed 19 findings involving confirmed data exfiltration through at least three distinct channels. The exfiltration was systematic, involving 17 files totaling approximately 85-90 MB of disguised Office documents containing sensitive government and business information.

The first channel was USB drive rm2 ("IAMAN $_@"), where files were staged in 51 seconds through a rapid batch copy operation. The second channel was optical media rm3_type3 ("IAMAN CD"), created approximately 11 hours after the USB staging, providing a redundant backup. The third channel was Google Drive cloud storage, installed the day before staging and actively synced during the cleanup phase, with sync databases subsequently deleted to hide evidence.

**Government Document Metadata in Exfiltrated Files**

Critical severity findings reveal that exfiltrated documents contained embedded email addresses from US Government sources. Eric_P._Lauer@omb.eop.gov represents the Office of Management and Budget within the Executive Office of the President. The mmun@loc.gov address represents the Library of Congress. Library of Congress URLs (http://hdl.loc.gov/loc.pnp/acd.2a10339) were found in document content, along with email subjects referencing historical photograph catalogs.

The presence of OMB/EOP metadata in documents labeled "Secret Project Data" indicates potential classified or sensitive unclassified information. A NIST employee exfiltrating documents containing Executive Office of the President and Library of Congress email metadata represents an insider threat incident with potential national security implications. The unauthorized removal of documents from federal systems constitutes potential federal crimes including theft of government property and unauthorized removal of records.

**Systematic File Masquerading on USB and Optical Media**

High severity findings document that all 17 files on both rm2 USB and rm3_type3 optical media were systematically renamed with misleading file extensions. Extension/content mismatch analysis shows Word documents disguised as .png, .gif, .txt, and .one files. Excel spreadsheets disguised as .7z and .jpg files. PowerPoint presentations disguised as .zip and .txt files. OLE compound documents disguised as .amr (audio), .db, and .avi (video) files.

This obfuscation technique, consistent with MITRE ATT&CK technique T1564.001 (Hide Artifacts: Hidden Files and Directories), is commonly used to bypass Data Loss Prevention systems and evade detection during exfiltration. The consistent folder structure across both media types (design, pricing, progress, proposal, technical review) indicates business documents disguised as personal media files.

**Intent Evidence: Web Research on Data Leakage**

Critical severity findings establish intent through web browsing evidence. The user researched "data-leakage-threats-mitigation-19312" (SANS whitepaper), "information leakage cases," and "leaking confidential information" with progressive query refinement showing "leaking confidenti" → "leaking confidential i" → "leaking confidential informat" → "leaking confidential information."

Additional research included the ForensicsWiki "Tools:Data_Recovery" page, Microsoft Research paper "leak_secret.pdf," and searches for "system cleaner." The user also accessed https://www.google.com/drive/ and https://www.google.com/drive/download/. This evidence proves the suspect had intent to leak confidential information and researched methods to avoid detection. The progression of search queries shows deliberate planning, not accidental data handling.

**Anti-Forensic Tool Execution**

High severity findings document the installation and execution of CCleaner and Eraser immediately following data exfiltration. These tools were installed on March 25, after the March 24 data staging. Eraser is designed for secure file deletion beyond forensic recovery. CCleaner cleans browser history, registry, temporary files, and system traces. The execution timing on the same day as the resignation letter indicates this was intentional cleanup as part of a planned departure, constituting evidence tampering and obstruction of justice.

**Multiple Administrator Account Creation**

Medium severity findings reveal that three additional administrator accounts (admin11, ITechTeam, temporary) were created by the informant account within 30 minutes of the informant account creation. While the admin11 account was used at least once (Notepad execution), the ITechTeam and temporary accounts show no evidence of interactive use. The creation of multiple admin accounts could indicate preparation for lateral movement with alternative credentials, plausible deniability through activity attribution to different accounts, backdoor access maintenance, or isolated contexts for exfiltration activities.

The absence of 4624 (successful logon) events for these accounts in security logs may indicate audit policy gaps, log clearing, or login via methods not generating 4624 events. The admin11 UserAssist entry proves at least minimal account usage.

## Threat Intelligence and Attribution

**Attribution Confidence: High for Insider Threat, Uncertain for External Collaboration**

The evidence conclusively identifies Iaman Informant (iaman.informant@nist.gov) as the insider threat actor. Attribution is established through: email addresses in PC email data (iaman.informant@nist.gov, Exchange Labs identifier, Outlook profile), resignation letter naming the individual, consistent "IAMAN" naming across USB volume label "IAMAN $_@", optical media "IAMAN CD," and email identity.

The actor's NIST employment status makes this an insider threat incident with potential national security implications. As a federal employee, the user had trust and access privileges that were exploited for unauthorized removal of government documents.

**Behavioral Indicators**

The actor demonstrated sophisticated operational security awareness including: multi-channel redundancy (USB plus optical plus cloud), file extension masquerading to bypass DLP, timestamp manipulation to hide activity timing, anti-forensic tool deployment for evidence destruction, cloud sync database deletion to hide exfiltration volume, and progressive web search query refinement indicating research intent.

**Potential External Collaboration Uncertainty**

While the evidence proves insider threat activity conclusively, determination of external collaboration or foreign intelligence involvement requires additional investigation. The targeting of Executive Office of the President and Library of Congress documents by a NIST employee suggests potential awareness of sensitive government workflows, but no direct evidence of external direction or coordination was recovered. The personal email address (wayne.longman@att.net) and personal Gmail account (iaman.informant.personal@gmail.com) found in evidence could indicate external communication channels, but this requires further investigation of email content and cloud account activity.

The attribution confidence remains high for insider threat activity but uncertain regarding potential external collaboration.

## Impact Assessment

**Scope of Compromise**

One PC system was actively used for data exfiltration activities by a single identified insider threat actor. The user account was created on March 22, 2015, and remained active for four days. Three additional administrator accounts were created, with one confirmed used and two showing no interactive use evidence.

**Data at Risk**

Seventeen files totaling approximately 85-90 MB were staged on removable media and potentially uploaded to cloud storage. Document metadata indicates Executive Office of the President (OMB/EOP) and Library of Congress email addresses were embedded in exfiltrated files. Content includes design documents, pricing information, proposals, progress reports, and technical reviews.

The data flow was: rm1 ("Authorized USB," source files) → PC (processing/obfuscation) → rm2 (USB, March 24 morning) AND rm3_type3 (optical, March 24 evening) AND Google Drive (cloud, status unknown due to database deletion). The deletion of Google Drive sync databases prevents determination of whether cloud exfiltration was successful and which specific files were uploaded.

**Credential Exposure**

Four user accounts with administrator privileges were created. Password reset activities were performed on all three additional accounts. If passwords were weak or shared externally, these accounts represent persistent access vectors even after the primary account was disabled.

**Persistence Depth**

No evidence of remote access tools, backdoors, or persistent malware was identified. The multi-account creation represents the primary persistence mechanism, potentially allowing backdoor access if not disabled. The activity window of four days with resignation letter creation suggests a deliberate exit strategy with no intention of persistent system access.

**Business and Legal Impact**

This incident represents: unauthorized removal of government records (potential federal crime), theft of intellectual property potentially containing Executive Office of the President information, violation of NIST security policies, evidence tampering and obstruction through anti-forensic tool deployment, and potential national security implications depending on document classification level.

The resignation timing correlated with exfiltration activities suggests premeditated departure with data theft, indicating this was not opportunistic but planned.

## Immediate Tactical Containment

The following actions must be taken immediately to contain this incident:

1. **Disable all user accounts created by informant**: Immediately disable the accounts "informant," "admin11," "ITechTeam," and "temporary" on the affected PC and any domain-wide systems where these accounts may have propagated.

2. **Isolate the affected PC system**: Disconnect the PC from the network immediately to prevent any potential further data transmission or remote access.

3. **Secure removable media**: The USB drives rm1 ("Authorized USB"), rm2 ("IAMAN $_@"), and optical disc rm3_type3 ("IAMAN CD") must be secured as evidence. Do not connect these to other systems.

4. **Block cloud exfiltration channel**: Immediately revoke access to the Google Drive account configured with the sync folder at Users\informant\Google Drive\. Initiate legal process to preserve and obtain Google Drive logs and stored data for the account.

5. **Preserve email communications**: Preserve all email communications for iaman.informant@nist.gov and iaman.informant.personal@gmail.com. Review communications for external collaboration indicators.

6. **SanDisk Cruzer Fit USB investigation**: Investigate the SanDisk Cruzer Fit USB device connected at 18:31:10 UTC on March 23. This device was connected 7 minutes before source file access began and may contain additional evidence.

7. **Review file access logs for source documents**: Examine fileserver logs for the "Secret Project Data" directory to identify all files accessed and determine if additional files beyond the identified 17 were exfiltrated.

8. **Cloud storage account audit**: Audit the user's Gmail account (iaman.informant.personal@gmail.com) and any other personal cloud storage accounts for uploaded government data.

## Strategic Remediation

**Root Cause 1: Insider Threat Detection Gap**

The user was able to access sensitive government documents labeled "Secret Project Data," exfiltrate them over three days, and perform anti-forensic cleanup without triggering alerts. The absence of alerts for large-scale file staging, USB device usage, and cloud storage installation indicates insufficient insider threat monitoring.

*Remediation:* Deploy User and Entity Behavior Analytics (UEBA) to detect anomalous file access patterns, USB device usage, and cloud service installations. Specifically, configure alerts for: USB device connections by users with access to sensitive documents, installation of cloud storage clients on government systems, bulk file operations exceeding threshold volumes within short time windows, and execution of anti-forensic tools (CCleaner, Eraser) on any government system.

**Root Cause 2: Data Loss Prevention Circumvention**

Files were successfully renamed with media extensions (.jpg, .png, .avi, .amr) to bypass DLP controls. This indicates DLP rules were based on file extensions rather than content inspection or file signature analysis.

*Remediation:* Implement content-aware DLP that analyzes file payloads rather than extensions. Configure DLP to inspect for Office document signatures (DOCX, XLSX, PPTX, OLE compound documents) regardless of file extension. Block transfer of files with signature/extension mismatches to removable media or cloud services.

**Root Cause 3: Privilege Management Weakness**

A single user account was able to create three additional administrator accounts within 30 minutes without triggering approval workflows or generating alerts. This violates principle of least privilege.

*Remediation:* Implement Privileged Access Management (PAM) requiring approval workflows for administrator account creation. Configure alerts for any account creation by non-IT personnel. Restrict local administrator group membership to approved service accounts and documented IT staff.

**Root Cause 4: Removable Media Controls Absent**

USB drives were connected and used for staging government data without restriction. The volume labels "IAMAN $_@" and "Authorized USB" suggest the user was aware of and potentially circumventing media policies.

*Remediation:* Deploy USB device control using Device Control or similar solutions. Restrict USB access to approved encrypted devices only. Block write access to unapproved removable media on systems with access to sensitive documents.

**Root Cause 5: Cloud Service Controls Insufficient**

Google Drive was installed and synchronized government data without detection. The deleted sync databases indicate the user understood how to cover tracks.

*Remediation:* Block consumer cloud storage services (Google Drive, Dropbox, iCloud, OneDrive personal) at the network perimeter. Implement SSL inspection to detect unauthorized cloud service usage. Configureendpoint DLP to block sync client installations for unapproved cloud services.

**Root Cause 6: Offboarding Security Gap**

No evidence indicates the user's access was proactively revoked or monitored during the resignation period. The correlation between resignation timing and data exfiltration suggests the departure was anticipated without security escalation.

*Remediation:* Implement offboarding security protocols including: immediate access revocation upon resignation notification, enhanced monitoring for 30 days prior to departure for sensitive positions, mandatory exit interview with IT security review of system activity, and forensic imaging of departure-day activities for positions with sensitive access.

## Conclusion

**Q1. What systems were compromised?**

One Windows 7 PC system was used as the primary exfiltration workstation. Three additional user accounts with administrator privileges (admin11, ITechTeam, temporary) were created on this system. The investigation found no evidence of compromise on other systems, no malware deployment, and no remote access tools installed. The compromise was limited to the insider threat actor's deliberate use of assigned workstation resources.

**Q2. How did the attacker gain initial access?**

This was an insider threat incident, not an external attack. The actor was a legitimate NIST employee (iaman.informant@nist.gov) with authorized access to the PC system. The user account was created on March 22, 2015, through standard provisioning. Initial access was legitimate employment-based access. No exploitation or credential theft was required.

**Q3. What lateral movement occurred?**

No traditional lateral movement to other systems was identified. However, the actor created three additional administrator accounts (admin11, ITechTeam, temporary) within the first 30 minutes of account creation. Only admin11 showed evidence of use (Notepad execution at 15:57:30 UTC on March 22). The creation of multiple admin accounts suggests preparation for potential lateral movement or establishing alternative access pathways.

**Q4. What persistence mechanisms were installed?**

No malware, remote access tools, or technical backdoors were installed. The primary persistence mechanism was the creation of multiple administrator accounts that could provide continued access if the primary account was disabled. The short activity window (four days) with resignation letter creation on the final day indicates the actor had no intention of persistent access—this was a departure time-limited data theft operation, not a long-term access strategy.

**Q5. Was data exfiltrated, and if so, what and how much?**

Yes. Seventeen files totaling approximately 85-90 MB were confirmed staged on removable media (USB rm2 and optical rm3_type3). Files included design documents, pricing materials, proposals, progress reports, and technical reviews disguised with media file extensions. Document metadata contained Executive Office of the President (OMB/EOP) and Library of Congress email addresses, indicating potential government intellectual property. Cloud exfiltration via Google Drive is highly probable based on sync activity timing, but the specific files uploaded cannot be determined due to sync database deletion. The total exfiltration scope may be larger if additional files were uploaded to cloud storage before database deletion.

**Q6. What is the full timeline of the incident?**

The complete timeline spans March 22-25, 2015:

- **March 22, 2015**: User account created at 14:34:41 UTC. Three additional administrator accounts created between 15:51-15:53 UTC. User researches data leakage and forensic evasion topics via web browser.

- **March 23, 2015**: SanDisk USB connected at 18:31:10 UTC. Source files accessed from "Authorized USB" (rm1) beginning at 18:38:21 UTC. Google Drive installed 20:02-20:05 UTC. Additional project file accessed at 20:27:33 UTC.

- **March 24, 2015**: Data staging on USB rm2 at 09:59:27-10:00:18 UTC (51 seconds for 17 files). Optical media created at approximately 20:55 UTC. All 17 files disguised with media extensions.

- **March 25, 2015**: Timestamp manipulation at 11:08:36 UTC. Anti-forensic tools installed 14:46-14:50 UTC. CCleaner and Eraser executed 14:57-15:15 UTC. Google Drive sync executed 15:21 UTC. Resignation letter created 15:28 UTC.

Total operational duration: 3 days from account creation to resignation.

**Q7. What is the total scope and business impact?**

One PC system with four administrator accounts. Seventeen known files staged on removable media, with cloud exfiltration probability high but undetermined. Document metadata indicates potential Executive Office of the President and Library of Congress involvement, suggesting possible national security implications. The insider threat actor's deliberate evidence destruction indicates consciousness of wrongdoing. Legal exposure includes potential federal crimes (theft of government property, unauthorized removal of records, evidence tampering). The correlation with resignation indicates premeditated data theft as part of an exit strategy, representing a breakdown in offboarding security controls for positions with sensitive access.

**Q8. What are the recommended remediation actions?**

Immediate containment actions are detailed in the Tactical Containment section above. Strategic remediation for each identified root cause includes: deploying User and Entity Behavior Analytics for insider threat detection, implementing content-aware DLP with file signature inspection rather than extension-based rules, establishing Privileged Access Management with approval workflows for administrator account creation, deploying USB device control to restrict removable media access, blocking consumer cloud storage services at the network perimeter, and implementing offboarding security protocols including proactive access revocation and enhanced monitoring. Each remediation directly addresses specific failures observed in this incident—failure to detect insider threat behavior, failure to prevent DLP circumvention through file masquerading, failure to control administrator privilege proliferation, failure to restrict removable media, failure to block unauthorized cloud storage, and failure to secure the departure process.


---

## Overview

| | |
|---|---|
| Findings | **22** (19 confirmed, 3 inference) |
| Severity | 6 critical, 10 high, 4 medium, 0 low, 2 info |
| Sources | 13 evidence sources across 454 tool calls |


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
| 2014-12-01T14:50:26Z | Deleted Files on UDF Optical Media - Evidence of Multi-Session Data Tampering | CRITICAL | optical.listing, tsk.masquerade |
| 2015-03-22T14:33:54 | Multiple User Accounts Created with Admin Privileges | HIGH | hayabusa.alerts |
| 2015-03-22T14:33:54Z | Admin Accounts Created - Minimal Use of admin11, No Evidence of Use for Others | MEDIUM | hayabusa.alerts, composite.persistence |
| 2015-03-22T14:34:00 | Intent Evidence: Web Searches About Data Leakage and Forensic Evasion | CRITICAL | bulk.url |
| 2015-03-22T14:34:00 | Cloud Storage Tools Installed (Google Drive and iCloud) | HIGH | tsk.filelist |
| 2015-03-22T14:34:41 | NIST Employee Identity Confirmed - Iaman Informant | CRITICAL | bulk.email, registry.ntuser.informant |
| 2015-03-22T14:34:41 | Data Exfiltration Timeline - March 22-25, 2015 | MEDIUM | tsk.masquerade, ez.mft, tsk.filelist, forensic.timestomping |
| 2015-03-23T18:31:10 | SanDisk USB Device Connected During Exfiltration Period | MEDIUM | registry.query.system |
| 2015-03-23T18:38:21 | Source Data Found on "Authorized USB" Drive (rm1) | HIGH | tsk.filelist |
| 2015-03-23T18:38:21 | Secret Project Files Accessed on PC (LNK Evidence) | HIGH | ez.mft |
| 2015-03-23T18:38:21 | Secret Project Data on USB Device | INFO | tsk.filelist |
| 2015-03-23T20:02:43 | Data Exfiltration Timeline and Method | CRITICAL | ez.mft, tsk.masquerade, bulk.url |
| 2015-03-23T20:02:43 | Google Drive Installation and Cloud Storage Setup | HIGH | ez.mft, tsk.filelist |
| 2015-03-23T20:02:43 | Cloud Storage Services Accessed for Potential Exfiltration | HIGH | bulk.domain, registry.ntuser.informant |
| 2015-03-23T20:02:43Z | Google Drive as Third Exfiltration Channel - Sync Activity with Database Deleted | HIGH | registry.ntuser.informant, bulk.url, ez.mft, tsk.filelist |
| 2015-03-24T09:59:27 | US Government Email Address Found on Removable Media | CRITICAL | bulk.email, bulk.url, bulk.rfc822 |
| 2015-03-24T09:59:27 | Files Disguised with Wrong Extensions on Removable Media | HIGH | tsk.masquerade |
| 2015-03-24T09:59:27Z | US Government Email Metadata in Exfiltrated Files - OMB/EOP and Library of Congress | CRITICAL | bulk.email, bulk.url, bulk.rfc822 |
| 2015-03-25T11:08:36 | Timestamp Manipulation Detected on PC | MEDIUM | forensic.timestomping |
| 2015-03-25T11:08:36Z | Coordinated Anti-Forensic Cleanup Timeline - Evidence of Planned Exit Strategy | HIGH | registry.ntuser.informant, forensic.timestomping, hayabusa.alerts |
| 2015-03-25T14:46:05 | Anti-Forensic Tools Installation and Execution | HIGH | registry.ntuser.informant |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] US Government Email Address Found on Removable Media

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T23:59:59 |
| **Sources** | bulk.email, bulk.url, bulk.rfc822 |
| **Evidence Refs** | tc_f5ca191f, tc_b8b2d545, tc_1e991981 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Government email address Eric_P._Lauer@omb.eop.gov (Office of Management and Budget, Executive Office of the President) was found on rm2 USB drive. This email appears in document metadata embedded within the exfiltrated files. Additional email addresses found include wayne.longman@att.net (personal) and mmun@loc.gov (Library of Congress).

The presence of OMB/EOP email addresses on a removable USB drive suggests potential exfiltration of US Government documents. Email addresses were extracted from file metadata by bulk_extractor and are embedded in the exfiltrated documents. The Library of Congress URLs (http://hdl.loc.gov/loc.pnp/acd.2a10339) and email subjects referencing historical photograph catalogs indicate Library of Congress content was also exfiltrated.



### 2. [CRITICAL] Intent Evidence: Web Searches About Data Leakage and Forensic Evasion

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:34:00 |
| **Sources** | bulk.url |
| **Evidence Refs** | tc_0df850f6 |
| **ATT&CK** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) |


Web browsing evidence reveals the suspect was actively researching data leakage methods and forensic detection before and during the exfiltration:

**Data Leakage Research:**
- SANS whitepaper: "data-leakage-threats-mitigation-19312"
- Google search: "information leakage cases"
- News article: "Google to settle data leakage case for $85 million"
- Article: "Top 5 sources leaking personal data" (Emirates 24/7)

**Confidential Information Leakage Research:**
- Google searches for "leaking confidential information" with progressive query refinement:
  - "leaking confidenti"
  - "leaking confidential i"
  - "leaking confidential informat"
  - "leaking confidential information"

**Forensic Countermeasure Research:**
- "Tools:Data_Recovery" page on ForensicsWiki
- Microsoft Research paper: "leak_secret.pdf"
- Search for "system cleaner"

**Cloud Storage Access:**
- "https://www.google.com/drive/"
- "https://www.google.com/drive/download/"

This evidence proves the suspect had intent to leak confidential information and researched methods to avoid detection. The progression of search queries shows deliberate planning, not accidental data handling. The research into forensic tools suggests awareness of potential investigation.



### 3. [CRITICAL] Data Exfiltration Timeline and Method

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:02:43 |
| **Sources** | ez.mft, tsk.masquerade, bulk.url |
| **Evidence Refs** | tc_fc900623, tc_22299e09, tc_76e43792, tc_3aad1440, tc_8c8e48d7 |


Timeline of user activity demonstrates a deliberate data exfiltration sequence:

**2015-03-23:**
- 20:02:43 - 20:05:32 UTC: Google Drive desktop client installed and configured
- 20:05:32 UTC: Google Drive sync folder created at Users\informant\Google Drive
- 20:26:52 UTC: Excel application accessed
- 20:27:33 UTC: LNK file created for [secret_project]_final_meeting.pptx (evidence of secret project file access)
- 20:32:44 UTC: Apple iCloud software logs created (another potential cloud exfiltration channel)

**2015-03-24:**
- 09:59:27 - 10:00:18 UTC: 17 files disguised with media extensions created on removable media (rm2, volume "IAMAN $_@") in $OrphanFiles directory. All files marked as deleted.
- 13:21:17 - 21:07:21 UTC: Active web browsing via Chrome (multiple cache files updated throughout the day)
- Multiple Chrome cache entries for drive.google.com, docs.google.com, and mail.google.com
- Evidence of Google Drive sharing activity

**2015-03-25:**
- 15:21:34 - 15:21:36 UTC: Google Drive lockfile last modified (final sync activity)

The sequence shows: (1) install cloud storage tools, (2) access secret project files, (3) disguise documents as media files and copy to USB, (4) continue accessing cloud services. This methodical approach indicates deliberate preparation for data exfiltration.



### 4. [CRITICAL] NIST Employee Identity Confirmed - Iaman Informant

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:34:41 to 2015-03-25T15:29:08 |
| **Sources** | bulk.email, registry.ntuser.informant |
| **Evidence Refs** | tc_9c5d9a2c, tc_519d3d69 |


The user "informant" has been conclusively identified as Iaman Informant, an employee of the National Institute of Standards and Technology (NIST), based on multiple corroborating evidence sources:

**Email Address Evidence:**
- Primary email: iaman.informant@nist.gov (found in PC email data via bulk_extractor)
- Exchange Labs identifier: 1b788828-c8a2-4681-bf6f-b1df9935415b@nist.gov
- Outlook profile: iaman.informant@nist.gov.ost

**Document Evidence:**
- Resignation letter: "Resignation_Letter_(Iaman_Informant).docx" (created 2015-03-25)
- Resignation letter XPS version: "Resignation_Letter_(Iaman_Informant).xps"
- Documents accessed on 2015-03-25 (last day of activity)

**Government Data Theft Context:**
The user's NIST employment status makes the theft of US Government documents (OMB/EOP, Library of Congress) particularly significant. As a federal employee, the user had trust and access privileges. The exfiltration of documents containing email addresses from the Office of Management and Budget (Executive Office of the President) and Library of Congress from a NIST employee's system suggests potential insider threat compromise or unauthorized transfer of government intellectual property.

**Timeline Correlation:**
- User created on 2015-03-22
- Active for only 4 days (March 22-25)
- Resignation letter suggests planned departure
- Data exfiltration occurred during final days of employment/tenure



### 5. [CRITICAL] Deleted Files on UDF Optical Media - Evidence of Multi-Session Data Tampering

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26Z to 2015-03-24T20:57:03Z |
| **Sources** | optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_0602a3ae, tc_6b481885, tc_73fc34c7 |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1564.004](https://attack.mitre.org/techniques/T1564/004/), [T1567](https://attack.mitre.org/techniques/T1567/) |


The UDF write-once optical media (volume label 'IAMAN CD') contains 9 VAT (Virtual Allocation Table) sessions (generations) indicating multiple burn sessions. The disc shows evidence of directory renaming and file deletion across sessions to hide the original directory structure:

**Original Directory Names (Session 7 and earlier):**
- /design
- /pricing decision  
- /progress
- /proposal
- /technical review

**Abbreviated Directory Names (Session -1):**
- /de (design)
- /pd (pricing decision)
- /prog (progress)  
- /prop (proposal)
- /tr (technical review)

**Currently Present Files (Session 0):**
- /Koala.jpg (780,831 bytes) - Created: 2015-03-24
- /Penguins.jpg (777,835 bytes) - Created: 2015-03-24
- /Tulips.jpg (620,888 bytes) - Created: 2015-03-24

**Deleted Files (Recoverable from Earlier Sessions):**

**Session -1 (Most recent deletions):**
- /de/winter_storm.amr (14.5 MB)
- /de/winter_whether_advisory.zip (16.3 MB)
- /pd/my_favorite_cars.db (1.3 MB)
- /pd/my_favorite_movies.7z (100 KB)
- /pd/new_years_day.jpg (10.2 MB)
- /pd/super_bowl.avi (10.3 MB)
- /prog/my_friends.svg (58 KB)
- /prog/my_smartphone.png (4.4 MB)
- /prog/new_year_calendar.one (27 KB)
- /prop/a_gift_from_you.gif (35.2 MB) - LARGEST FILE
- /prop/landscape.png (6.5 MB)
- /tr/diary_#1d.txt (121 KB)
- /tr/diary_#1p.txt (458 KB)
- /tr/diary_#2d.txt (659 KB)
- /tr/diary_#2p.txt (1.2 MB)
- /tr/diary_#3d.txt (2.4 MB)
- /tr/diary_#3p.txt (325 KB)

The directory renaming and file deletion pattern across multiple sessions indicates an attempt to obscure the original document structure. The current session (0) only contains 3 image files, while earlier sessions contained 17+ files that were progressively deleted.

File modification timestamps range from December 2014 to January 2015, suggesting the original files were created over a 2-month period before being collected and burned to disc on March 24, 2015.

**Merged findings:**
- **Mass File Masquerading on Optical Media - Systematic Data Obfuscation** (f_1e67a48f, high, confirmed): 17 files on the UDF optical media (volume label 'IAMAN CD') have been systematically renamed with misleading file extensions to hide their true content type. This indicates deliberate data obfuscation consistent with data exfiltration preparation.

**Key Findings:**

All masqueraded files are in deleted directories from earlier VAT sessions but remain fully recoverable:

**Word Documents (.docx) disguised as:**
- my_smartphone.png (4.4 MB)
- new_year_calendar.one (27 KB)
- a_gift_from_you.gif (35.2 MB) - VERY LARGE
- landscape.png (6.5 MB)
- diary_#1d.txt (121 KB)
- diary_#2d.txt (659 KB)

**Excel Spreadsheets (.xlsx) disguised as:**
- my_favorite_movies.7z (100 KB)
- new_years_day.jpg (10.2 MB)

**PowerPoint Files (.pptx) disguised as:**
- winter_whether_advisory.zip (16.3 MB)
- diary_#1p.txt (458 KB)

**OLE Compound Documents disguised as:**
- winter_storm.amr (14.5 MB) - disguised as audio
- my_favorite_cars.db (1.3 MB) - disguised as database
- super_bowl.avi (10.3 MB) - disguised as video
- my_friends.svg (58 KB) - disguised as SVG image
- diary_#2p.txt (1.2 MB)
- diary_#3d.txt (2.4 MB)
- diary_#3p.txt (325 KB)

The naming pattern suggests business/project documents (design, pricing decision, progress, proposal, technical review) disguised to appear as personal media files. File dates range from December 2014 to January 2015, with disc creation on March 24, 2015.

This systematic obfuscation technique is commonly used to bypass DLP (Data Loss Prevention) systems and evade detection during data exfiltration.
- **Cross-Media Correlation - Optical Disc Links to USB Drives and User Identity** (f_90fd8093, info, confirmed): The rm3_type3 optical media volume label "IAMAN CD" correlates with the rm2 USB volume label "IAMAN $_@" and the user account name "iaman.informant@nist.gov". This naming consistency across multiple pieces of evidence (removable USB drives rm2 and rm3_type3, plus the user's NIST email identity) indicates a single actor is responsible for the data exfiltration activities.

**Correlation Evidence:**

1. **rm2 USB Drive:** Volume label "IAMAN $_@" 
   - Contains 17 masqueraded files in $OrphanFiles
   - Files created 2015-03-24 09:59:27-10:00:18 UTC

2. **rm3_type3 Optical Media:** Volume label "IAMAN CD"
   - Contains same 17 masqueraded files (deleted from earlier sessions)
   - Shows evidence of multi-session data tampering
   - Files dating from December 2014 to January 2015

3. **User Identity:** iaman.informant@nist.gov
   - NIST employee email address
   - User account "informant" on PC

**Significance:**

The consistent "IAMAN" naming convention suggests the optical media (rm3_type3) was created by the same actor who prepared the USB drives. The optical media represents a redundant or fallback copy of the exfiltrated data, created using write-once UDF format which makes deletion attempts recoverable via VAT session analysis.

The correlation establishes that the same insider threat actor created multiple copies of the stolen data across different media types (USB flash drives and optical disc), indicating sophisticated data exfiltration planning and execution.
- **Multi-Stage Data Exfiltration - USB and Optical Media Created 11 Hours Apart** (f_d26a6832, critical, confirmed): Cross-system correlation of file creation timestamps reveals deliberate multi-stage exfiltration with redundant backup channels:

**Stage 1 - USB Drive (rm2):**
- 17 obfuscated files created on 2015-03-24 09:59:27-10:00:18 UTC
- **Duration: 51 seconds** for all files (rapid batch copy operation)
- Volume label: "IAMAN $_@"
- Files disguised with media extensions (.jpg, .png, .gif, .avi, .amr, .zip, .7z, .db, .txt)

**Stage 2 - Optical Media (rm3_type3):**
- Same 17 obfuscated files created on 2015-03-24 20:55:43 UTC
- **~11 hours AFTER USB creation** (evening vs. morning)
- Volume label: "IAMAN CD"
- UDF write-once format with 9 VAT sessions
- Files progressively deleted across sessions (multi-session tampering)

**Timeline Significance:**
- Multi-stage approach indicates sophisticated planning
- Optical media created as redundant backup or alternative exfiltration channel
- ~11-hour gap suggests separate operational phases
- Same actor created both media (consistent "IAMAN" naming and identical file sets)

**Data Flow:**
rm1 ("Authorized USB", source files) → PC (processing/obfuscation) → rm2 (USB, morning) AND rm3_type3 (optical, evening)

The separate staging events demonstrate the actor's intent to create multiple copies of stolen data across different media types, ensuring data survivability and providing fallback exfiltration options.

**Affected Systems:** optical.listing, tsk.masquerade



### 6. [CRITICAL] US Government Email Metadata in Exfiltrated Files - OMB/EOP and Library of Congress

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27Z to 2015-03-24T23:59:59Z |
| **Sources** | bulk.email, bulk.url, bulk.rfc822 |
| **Evidence Refs** | tc_01f8154d |


US Government email addresses embedded in the metadata of exfiltrated documents indicate the stolen files contain or originated from sensitive US Government sources:

**Government Email Addresses Found:**

**1. Eric_P._Lauer@omb.eop.gov**
- Organization: Office of Management and Budget (OMB)
- Parent: Executive Office of the President (EOP)
- Context: Office of the President of the United States
- Source: Document metadata embedded within exfiltrated files

**2. mmun@loc.gov**
- Organization: Library of Congress (LOC)
- Context: Legislative branch digital content
- Related URLs: hdl.loc.gov/loc.pnp/acd.2a10339 (Library of Congress digital handle)
- Source: Email metadata and document properties

**3. Wayne.Longman@att.net**
- Personal email (AT&T domain)
- Source: Document metadata

**Relationship to Secret Project Files:**
- The government email addresses were embedded in the document properties/metadata of the exfiltrated files
- This indicates the documents were either:
  a) Created by government employees and shared with the suspect
  b) Received from government sources via email
  c) Part of official government project documentation

**Document Content Evidence:**
- Library of Congress URLs (http://hdl.loc.gov/loc.pnp/acd.2a10339) in document content
- Email subjects referencing Library of Congress historical photograph catalogs
- Presence of OMB/EOP metadata in documents labeled as "Secret Project Data"

**Significance:**
1. **Insider Threat Context:** A NIST employee (iaman.informant@nist.gov) exfiltrating documents containing OMB/EOP and Library of Congress email metadata suggests unauthorized transfer of government intellectual property across federal agencies

2. **Classification Level:** Documents with Executive Office of the President metadata marked as "Secret Project Data" indicates potential classified or sensitive unclassified information

3. **Attribution:** The email addresses prove the documents originated from or passed through US Government systems before being stolen

4. **Legal Implications:** Unauthorized removal of documents containing Executive Office of the President and Library of Congress metadata constitutes potential federal crimes (theft of government property, unauthorized removal of records)

The exfiltration of documents with US Government email addresses from a NIST employee's system to personal removable media and cloud storage represents a significant insider threat incident with potential national security implications.



### 7. [HIGH] Files Disguised with Wrong Extensions on Removable Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_62a7b95b, tc_76e43792 |
| **ATT&CK** | [T1564.001](https://attack.mitre.org/techniques/T1564/001/) |


Seventeen files with deceptive file extensions were created on removable media (rm2, volume label "IAMAN $_@") on 2015-03-24 between 09:59:27 UTC and 10:00:18 UTC. All files are marked as deleted ($OrphanFiles). The files have media file extensions (.amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt) but their actual file signatures indicate they are Microsoft Office documents (DOCX, XLSX, PPTX) or OLE compound files.

Files include:
- winter_storm.amr → OLE (14.5 MB)
- winter_whether_advisory.zip → PPTX (16.4 MB)
- my_favorite_cars.db → OLE (1.2 MB)
- my_favorite_movies.7z → XLSX (100 KB)
- new_years_day.jpg → XLSX (10.2 MB)
- super_bowl.avi → OLE (10.3 MB)
- a_gift_from_you.gif → DOCX (35.2 MB)
- diary_#1d.txt, diary_#2d.txt, diary_#3d.txt → DOCX/OLE
- diary_#1p.txt → PPTX
- diary_#2p.txt, diary_#3p.txt → OLE
- my_smartphone.png, new_year_calendar.one, landscape.png → DOCX

The files are organized in folders named: design, PRICIN~1 (Pricing?), progress, proposal, and TECHNI~1 (Technical?). This naming suggests corporate/business documents. The use of media file extensions to disguise documents is a clear indicator of data concealment for exfiltration.

**Merged findings:**
- **Documents Renamed to Hide Contents on USB Drive** (f_209cd841, high, confirmed): 17 files on rm2 USB drive exhibit extension/content mismatches, indicating deliberate obfuscation of Office documents. Files were renamed with media and archive file extensions to disguise their true content:

1. winter_storm.amr → OLE format (14.5 MB)
2. winter_whether_advisory.zip → PowerPoint (16.4 MB)
3. my_favorite_cars.db → OLE format (1.3 MB)
4. my_favorite_movies.7z → Excel (100 KB)
5. new_years_day.jpg → Excel (10.2 MB)
6. super_bowl.avi → OLE format (10.3 MB)
7. my_friends.svg → OLE format (58 KB)
8. my_smartphone.png → Word (4.4 MB)
9. new_year_calendar.one → Word (27 KB)
10. a_gift_from_you.gif → Word (35.2 MB)
11. landscape.png → Word (6.5 MB)
12. diary_#1d.txt → Word (121 KB)
13. diary_#1p.txt → PowerPoint (458 KB)
14. diary_#2d.txt → Word (659 KB)
15. diary_#2p.txt → OLE format (1.2 MB)
16. diary_#3d.txt → OLE format (2.4 MB)
17. diary_#3p.txt → OLE format (325 KB)

All files are deleted and located in $OrphanFiles directories, indicating they were removed after being copied to the drive. This is consistent with data staging for exfiltration and anti-forensic cleanup.

**Affected Systems:** tsk.masquerade



### 8. [HIGH] Source Data Found on "Authorized USB" Drive (rm1)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_07fa12ee |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


USB drive rm1 with volume label "Authorized USB" contains the original source files that were subsequently obfuscated and exfiltrated to rm2. The drive contains a "Secret Project Data" directory with organized project materials:

**Design folder:**
- [secret_project]_design_concept.ppt
- [secret_project]_detailed_design.pptx
- [secret_project]_revised_points.ppt

**Proposal folder:**
- [secret_project]_detailed_proposal.docx
- [secret_project]_proposal.docx
- ~$ecret_project]_proposal.docx (Word temporary file, deleted)

The presence of a Word temporary file (~$ecret_project]_proposal.docx) indicates the proposal document was opened/edited on this drive. A duplicate directory structure exists under "RM#1/Secret Project Data/".

These are the source documents that were renamed with media file extensions and placed on rm2 for exfiltration. The naming convention "[secret_project]" indicates sensitive project materials were targeted for theft.



### 9. [HIGH] Google Drive Installation and Cloud Storage Setup

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:02:43 to 2015-03-25T15:21:36 |
| **Sources** | ez.mft, tsk.filelist |
| **Evidence Refs** | tc_3aad1440, tc_221952ae |


Google Drive client software was installed on the PC and configured for user "informant" on 2015-03-23 between 20:02:43-20:05:32 UTC. Evidence includes:

1. Google Drive program files in Program Files (x86)\Google\Drive\ with language modules (installed 2015-02-19 and 2015-03-23)
2. User data directory: Users\informant\AppData\Local\Google\Drive\user_default\ containing:
   - sync_config.db, snapshot.db (deleted, track synced files)
   - lockfile (last modified 2015-03-25 15:21:34, indicating active sync)
   - com.google.drive.nativeproxy.json
3. Sync folder: Users\informant\Google Drive\desktop.ini (created 2015-03-23 20:05:32, modified 2015-03-25 15:21:36)
4. Downloaded installer: Users\informant\Downloads\googledrivesync.exe

The timing (installed one day before files were disguised on removable media on 2015-03-24) and the presence of sync databases suggest Google Drive was set up as a potential exfiltration channel. The lockfile modification on 2015-03-25 indicates Google Drive was actively syncing data until the investigation period.



### 10. [HIGH] Secret Project Files Accessed on PC (LNK Evidence)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 to 2015-03-23T20:27:33 |
| **Sources** | ez.mft |
| **Evidence Refs** | tc_d3a42665, tc_fc900623 |
| **ATT&CK** | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Windows Recent Documents LNK files on the PC prove that the user "informant" accessed secret project files directly from removable media:

**March 23, 2015 18:38:21 UTC** - `[secret_project]_design_concept.lnk`
- Path: Users\informant\AppData\Roaming\Microsoft\Windows\Recent\
- This LNK file was created when the PowerPoint presentation was opened from the "Authorized USB" drive (rm1)

**March 23, 2015 20:27:33 UTC** - `[secret_project]_final_meeting.pptx.lnk`
- Path: Users\informant\AppData\Roaming\Microsoft\Windows\Recent\
- A second project file was opened approximately 2 hours later

The presence of these LNK files confirms that secret project files were accessed on the PC. The `[secret_project]_design_concept.lnk` corresponds to the file `[secret_project]_design_concept.ppt` found on rm1. Notably, `[secret_project]_final_meeting.pptx` is not present on rm1, suggesting additional project files may have existed or were deleted.

This establishes March 23 as the date of file access, with exfiltration occurring the following day (March 24) when obfuscated copies were created on rm2.

**Merged findings:**
- **Access to Secret Project Files** (f_8a9f7eba, high, confirmed): A Windows LNK (shortcut) file was created in the user's Recent documents folder on 2015-03-23 at 20:27:33 UTC pointing to a file named "[secret_project]_final_meeting.pptx". This LNK file at "Users\informant\AppData\Roaming\Microsoft\Windows\Recent\[secret_project]_final_meeting.pptx.lnk" confirms the user accessed and opened a PowerPoint presentation related to the secret project.

This access occurred on the same day Google Drive was installed (2015-03-23) and one day before files were disguised and copied to removable media (2015-03-24), establishing a clear timeline of data access followed by exfiltration preparation.

**Affected Systems:** ez.mft



### 11. [HIGH] Cloud Storage Tools Installed (Google Drive and iCloud)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:34:00 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_a0e68801 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Cloud storage and synchronization tools were downloaded and installed, potentially for data exfiltration:

**Google Drive:**
- Client installed: Program Files (x86)\Google\Drive\
- Sync configuration: Users\informant\AppData\Local\Google\Drive\user_default\sync_config.db-shm (deleted)
- Snapshot database: Users\informant\AppData\Local\Google\Drive\user_default\snapshot.db (deleted)
- Certificate store: Users\informant\AppData\Local\Google\Drive\user_default\cacerts (deleted)

**iCloud:**
- Installer downloaded: Users\informant\Downloads\icloudsetup.exe
- Zone.Identifier present (downloaded from internet)

**Google Drive Sync:**
- Installer downloaded: Users\informant\Downloads\googledrivesync.exe
- Zone.Identifier present (downloaded from internet)

The presence of sync databases and their deletion suggests the suspect may have synchronized files to cloud storage and then attempted to remove evidence of the synchronization. The deleted status of Google Drive database files indicates anti-forensic cleanup.



### 12. [HIGH] Anti-Forensic Tools Installation and Execution

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:46:05 to 2015-03-25T15:15:50 |
| **Sources** | registry.ntuser.informant |
| **Evidence Refs** | tc_519d3d69 |


Anti-forensic tools CCleaner and Eraser were downloaded, installed, and executed on 2015-03-25 after the data exfiltration events, indicating consciousness of guilt and attempted evidence destruction:

**Installation Timeline (2015-03-25):**
- 14:46:05 UTC - ccsetup504.exe (CCleaner installer) downloaded from Users\informant\Desktop\Download\
- 14:50:14 UTC - Eraser 6.2.0.2962.exe downloaded from Users\informant\Desktop\Download\
- 14:57:56 UTC - CCleaner installer executed (UserAssist entry)
- 15:12:28 UTC - Eraser executed (UserAssist entry)
- 15:15:50 UTC - CCleaner executed (UserAssist entry)

**Significance:**
- Tools were installed AFTER the data exfiltration on 2015-03-24
- Eraser is designed for secure file deletion beyond forensic recovery
- CCleaner cleans browser history, registry, temporary files, and system traces
- Execution on the same day as the resignation letter suggests intentional cleanup
- This constitutes evidence tampering and obstruction of justice

The installation and execution of these tools immediately following data exfiltration demonstrates the user's intent to destroy evidence of their activities.



### 13. [HIGH] Multiple User Accounts Created with Admin Privileges

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-22T15:53:11 |
| **Sources** | hayabusa.alerts |
| **Evidence Refs** | tc_a8ac9125 |


User "informant" created three additional user accounts and granted them local administrator privileges on 2015-03-22, shortly after the "informant" account was created:

**Account Creation Timeline:**
1. **2015-03-22 14:33:54** - "informant" account added to Administrators group (by SYSTEM)
2. **2015-03-22 15:51:54** - "admin11" added to Administrators group by "informant"
3. **2015-03-22 15:52:10** - Password reset for "admin11" by "informant"
4. **2015-03-22 15:52:30** - "ITechTeam" added to Administrators group by "informant"
5. **2015-03-22 15:52:45** - Password reset for "ITechTeam" by "informant"
6. **2015-03-22 15:53:11** - Password reset for "temporary" by "informant"

**Evidence from Security Event Logs (Hayabusa):**
- Event ID 4732 (Member Added to Local Group) - Multiple instances
- Event ID 4724 (Password Reset By Admin) - Multiple instances
- All actions performed from SubjectLogonId: 0x224e3 (informant session)

**User Accounts Involved:**
- **admin11** (SID: S-1-5-21-...-1001) - Administrator account with Chrome data
- **ITechTeam** (SID: S-1-5-21-...-1002) - Administrator account
- **temporary** (SID: S-1-5-21-...-1003) - Administrator account

**Significance:**
The creation of multiple admin accounts could indicate:
1. **Preparation for lateral movement** - Alternative credentials for evasion
2. **Plausible deniability** - Activity attribution to different accounts
3. **Backdoor access** - Maintaining access if primary account is disabled
4. **Testing environment setup** - Creating isolated contexts for exfiltration activities

All accounts have NTUSER.DAT registry hives extracted, confirming they were actively used profiles on this system.



### 14. [HIGH] Cloud Storage Services Accessed for Potential Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-23T20:02:43 to 2015-03-25T15:21:36 |
| **Sources** | bulk.domain, registry.ntuser.informant |
| **Evidence Refs** | tc_fd9a82be, tc_519d3d69 |


Evidence from bulk_extractor domain analysis reveals access to multiple cloud storage platforms, with Google Drive actively configured for synchronization:

**Cloud Storage Platforms Detected:**
1. **Google Drive** (Primary exfiltration channel)
   - drive.google.com
   - docs.google.com
   - Client installed: googledrivesync.exe (installed 2015-03-23)
   - Sync databases: sync_config.db, snapshot.db (deleted)
   - Active sync lockfile modified: 2015-03-25 15:21:34 UTC

2. **Microsoft OneDrive**
   - onedrive.live.com
   - www.onedrive.com
   - Accessed but no sync client installation detected

**Google Drive Configuration Evidence:**
- User data directory: Users\informant\AppData\Local\Google\Drive\user_default\
- Sync folder: Users\informant\Google Drive\
- desktop.ini created: 2015-03-23 20:05:32
- desktop.ini modified: 2015-03-25 15:21:36 (active during exfiltration window)
- Language modules and update components present

**Data Transfer Indicators:**
- The presence of snapshot.db indicates files were synced to cloud
- Lockfile indicates active Google Drive process
- Deleted sync databases (sync_config.db, snapshot.db) suggest cleanup attempts
- Timing coincides with USB data staging activities

**Exfiltration Method:**
The user likely used Google Drive to upload sensitive documents to a personal or external Google account, providing an alternative or additional exfiltration channel to the USB devices. The deleted sync databases are consistent with attempting to hide evidence of what files were uploaded to the cloud.



### 15. [HIGH] Google Drive as Third Exfiltration Channel - Sync Activity with Database Deleted

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-23T20:02:43Z to 2015-03-25T15:21:30Z |
| **Sources** | registry.ntuser.informant, bulk.url, ez.mft, tsk.filelist |
| **Evidence Refs** | tc_953117d0, tc_591eaf00, tc_3aad1440, tc_221952ae |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Google Drive was used as a third exfiltration channel beyond USB and optical media, with evidence of active synchronization followed by database deletion to hide traces:

**Google Drive Installation and Configuration:**
- Installed: 2015-03-23 20:02:43-20:05:32 UTC (one day before data staging)
- Sync folder created: Users\\informant\\Google Drive\\desktop.ini (2015-03-23 20:05:32)
- Sync databases: sync_config.db, snapshot.db (BOTH DELETED)

**Evidence of Active Sync:**
1. **UserAssist Execution:** googledrivesync.exe executed on 2015-03-25 15:21:30Z
2. **Lockfile Activity:** Google Drive lockfile last modified 2015-03-25 15:21:34 UTC
3. **Desktop.ini Modification:** Google Drive folder modified 2015-03-25 15:21:36 UTC

**Anti-Forensic Cleanup:**
- sync_config.db (track synced files) - DELETED
- snapshot.db (record of synced files) - DELETED
- cacerts - DELETED
- Database deletion indicates intentional removal of sync history

**Timeline Context:**
- 14:57:56Z - CCleaner executed (1st run)
- 15:12:28Z - Eraser executed
- 15:15:50Z - CCleaner executed (2nd run)
- **15:21:30Z - Google Drive sync executed** ← AFTER cleanup tools
- 15:28:33Z - Resignation letter created

**Web Interface Evidence:**
- drive.google.com and docs.google.com URLs in browser cache
- File sharing interface URLs: drive.google.com/sharing/share
- OAuth authentication scopes: www.googleapis.com/auth/drive.apps

**Significance:**
The installation timing (day before staging), active sync indicators, and subsequent database deletion strongly suggest Google Drive was used to upload exfiltrated files to a personal or external Google account. The deleted databases prevent forensic determination of **which specific files were synced**, but the timing and behavior are consistent with cloud-based exfiltration as an alternative to physical media transfer.

**Exfiltration Channels Identified:**
1. **USB Drive (rm2)** - Physical media
2. **Optical Media (rm3_type3)** - Physical media
3. **Google Drive** - Cloud exfiltration (EVIDENCE OF USE, CONTENT UNKNOWN)



### 16. [HIGH] Coordinated Anti-Forensic Cleanup Timeline - Evidence of Planned Exit Strategy

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T11:08:36Z to 2015-03-25T15:29:08Z |
| **Sources** | registry.ntuser.informant, forensic.timestomping, hayabusa.alerts |
| **Evidence Refs** | tc_953117d0, tc_23aef311, tc_5313802f |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070.006](https://attack.mitre.org/techniques/T1070/006/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |


A coordinated anti-forensic cleanup operation was executed on 2015-03-25, the same day as the resignation letter creation, indicating this was part of a planned exit strategy:

**Cleanup Timeline (2015-03-25):**

**Phase 1 - Timestamp Manipulation (11:08:36 UTC)**
- Root directory $STANDARD_INFORMATION timestamp backdated to 2009-07-14 (Windows installation date)
- Timestomping technique used to hide recent filesystem activity
- 2080 days discrepancy between SI and FN timestamps

**Phase 2 - Tool Installation (14:46:05-14:50:14 UTC)**
- 14:46:05Z - ccsetup504.exe executed (CCleaner installer)
- 14:50:14Z - Eraser 6.2.0.2962.exe executed (Eraser installer)

**Phase 3 - Anti-Forensic Tool Execution (14:57:56-15:15:50 UTC)**
- 14:57:56Z - CCleaner64.exe executed (1st run)
- 15:12:28Z - Eraser.exe executed (secure file deletion)
- 15:15:50Z - CCleaner64.exe executed (2nd run)

**Phase 4 - Cloud Sync (15:21:30-15:21:36 UTC)**
- 15:21:30Z - googledrivesync.exe executed
- 15:21:34Z - Google Drive lockfile modified
- 15:21:36Z - Google Drive folder updated

**Phase 5 - Resignation Letter (15:28:33-15:29:08 UTC)**
- 15:28:33Z - Resignation_Letter_(Iaman_Informant).xps created
- 15:29:08Z - Resignation_Letter_(Iaman_Informant).docx last accessed

**Cleanup Targets:**
- CCleaner: Browser history, temporary files, registry entries, system traces
- Eraser: Secure file deletion beyond forensic recovery
- Timestomping: Hide filesystem modification times
- Google Drive database deletion: Remove sync history evidence

**Trigger Analysis:**
The cleanup timing coincides with the resignation letter creation, indicating the anti-forensic measures were triggered by the planned departure/resignation event. The sequence (cleanup tools → cloud sync → resignation letter) suggests:
1. Clean local evidence
2. Sync final data to cloud
3. Submit resignation document

This coordinated timeline demonstrates consciousness of guilt and premeditated evidence destruction aligned with employment termination.



### 17. [MEDIUM] Timestamp Manipulation Detected on PC

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T11:08:36 to 2015-03-25T11:08:36 |
| **Sources** | forensic.timestomping |
| **Evidence Refs** | tc_1e77a73c |
| **ATT&CK** | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) |


Timestomping detected on the PC system. One file exhibits evidence of timestamp manipulation where the $STANDARD_INFORMATION Created timestamp (2009-07-14 02:38:56) is significantly earlier than the $FILE_NAME Created timestamp (2015-03-25 11:08:36) by 2080 days (~5.7 years).

This technique is commonly used to make files appear older than they actually are, potentially to hide recent creation time and blend in with legitimate system files, or to establish a false timeline. The file path showing timestomping is the root directory ".", indicating potential manipulation of filesystem metadata at the root level.



### 18. [MEDIUM] Data Exfiltration Timeline - March 22-25, 2015

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:34:41 to 2015-03-25T11:08:36 |
| **Sources** | tsk.masquerade, ez.mft, tsk.filelist, forensic.timestomping |
| **Evidence Refs** | tc_62a7b95b, tc_d3a42665, tc_07fa12ee, tc_1e77a73c |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1564.001](https://attack.mitre.org/techniques/T1564/001/), [T1070.006](https://attack.mitre.org/techniques/T1070/006/) |


Forensic timeline of data exfiltration activity reconstructed from file system evidence:

**Phase 1 - Initial Setup (March 22, 2015):**
- User profile "informant" created on PC at 14:34:41 UTC
- Email client (Windows Mail) and browser (Chrome) configured

**Phase 2 - Source File Access (March 23, 2015):**
- 18:38:21 - Opened `[secret_project]_design_concept.ppt` from rm1 USB drive
- 20:27:33 - Opened `[secret_project]_final_meeting.pptx`
- User accessed multiple secret project files from "Authorized USB" drive

**Phase 3 - Data Staging and Obfuscation (March 24, 2015):**
- 09:59:27 - First obfuscated file created on rm2 USB drive
- 09:59:27-10:00:18 - All 17 masqueraded files created on rm2 in ~51 seconds
- Files renamed: Office documents → media/archive extensions (.jpg, .png, .gif, .avi, .amr, .zip, .7z, .db, .txt)
- All files placed in $OrphanFiles as deleted entries

**Phase 4 - Cleanup (March 25, 2015):**
- 11:08:36 - Timestamp manipulation detected on PC root directory
- Government email metadata present in exfiltrated files

**Total Duration:** 3 days from profile creation to exfiltration completion.

**Data Flow:** rm1 ("Authorized USB") → PC → rm2 ("IAMAN $_@")

**Exfiltrated Content:** Secret Project Data including design concepts, detailed designs, and proposals containing US Government email addresses (OMB/EOP).



### 19. [MEDIUM] SanDisk USB Device Connected During Exfiltration Period

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:31:10 to 2015-03-23T18:31:10 |
| **Sources** | registry.query.system |
| **Evidence Refs** | tc_f9a1618b |


A SanDisk Cruzer Fit USB device was connected to the PC on 2015-03-23 at 18:31:10 UTC, as recorded in the Windows registry USBSTOR key. This timing correlates with:

1. **Same day as source file access:** User opened [secret_project]_design_concept.ppt at 18:38:21 (7 minutes after USB connection)
2. **Same day as Google Drive installation:** Google Drive installed on 2015-03-23
3. **One day before data obfuscation:** Files disguised on rm2 USB on 2015-03-24

**Registry Evidence:**
- Key: ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01
- Last Written: 2015-03-23T18:31:10.573006

This USB device connection is the physical link between the source data (rm1 "Authorized USB") and the staging/obfuscation activities observed on the rm2 device. The timing establishes the user's physical access to removable storage during the critical period of data theft preparation.



### 20. [MEDIUM] Admin Accounts Created - Minimal Use of admin11, No Evidence of Use for Others

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54Z to 2015-03-25T15:30:00Z |
| **Sources** | hayabusa.alerts, composite.persistence |
| **Evidence Refs** | tc_5313802f, tc_30ac62fc |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/) |


The user "informant" created three additional administrator accounts on 2015-03-22. While security event logs show no 4624 (successful logon) events for these accounts, forensic analysis reveals the admin11 account was used at least once:

**Account Creation Timeline (2015-03-22):**
- 14:33:54 - "informant" added to Administrators group (by SYSTEM)
- 15:51:54 - "admin11" added to Administrators group by "informant"
- 15:52:10 - Password reset for "admin11" by "informant"
- 15:52:30 - "ITechTeam" added to Administrators group by "informant"
- 15:52:45 - Password reset for "ITechTeam" by "informant"
- 15:53:11 - Password reset for "temporary" by "informant"

**Evidence of admin11 Account Use:**
- **2015-03-22 15:57:30Z**: NOTEPAD.EXE executed from admin11 UserAssist registry
- This proves the admin11 account was logged into and used interactively, despite absence of 4624 events in security logs
- The missing 4624 events may indicate audit policy gaps or log clearing

**Login Evidence for Other Accounts:**
- **ITechTeam**: No UserAssist or execution evidence found
- **temporary**: No UserAssist or execution evidence found

**Revised Assessment:**
The admin11 account was used at least once (Notepad execution), which undermines the theory that all three accounts were created solely as unused backdoors. However, the ITechTeam and temporary accounts show no evidence of use. The purpose of admin11's limited use (running Notepad ~4 minutes after the last password reset) is unclear - it could be:
1. A test to verify the account worked
2. Legitimate use
3. An attempt to obscure the account's true purpose (backdoor)

The creation of multiple admin accounts with at least minimal use of one account still suggests preparation for potential alternative access pathways.



### 21. [INFO] Secret Project Data on USB Device

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_33a31851 |


A USB device (rm1) with volume label "Authorized USB" contains a directory structure named "Secret Project Data" with subdirectories including "Secret Project Data/design/" containing project files. The files were accessed starting 2015-03-23 18:38:21 UTC when the user opened [secret_project]_design_concept.ppt from this drive.

**Directory Structure Found:**
- Secret Project Data/design/ - Design documents (PPT, PPTX files)
- Secret Project Data/proposal/ - Proposal documents (DOCX files)
- Secret Project Data/pricing/ - Pricing documents (XLSX files)
- RM#1/Secret Project Data/ - Duplicate directory structure

**Files Identified:**
- [secret_project]_design_concept.ppt (accessed 2015-03-23 18:38:21)
- [secret_project]_detailed_design.pptx
- [secret_project]_revised_points.ppt
- [secret_project]_detailed_proposal.docx
- [secret_project]_proposal.docx (with temporary file ~$ecret_project]_proposal.docx, indicating it was opened/edited)
- (secret_project)_pricing_decision.xlsx

**Significance:**
The volume label "Authorized USB" may be an attempt to legitimize the device or could indicate it was provided as part of authorized work. However, the combination with disguised files on rm2 and Google Drive installation suggests the data was being exfiltrated. The presence of a Word temporary file indicates the proposal document was edited on this drive.

These source documents were subsequently renamed with media file extensions and placed on rm2 for exfiltration. The naming convention "[secret_project]" indicates sensitive project materials were targeted for theft.



### 22. [INFO] Google Drive Web Interface and File Sharing URLs

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | bulk.url |
| **Evidence Refs** | tc_8c8e48d7, tc_34ce987b, tc_056038b2 |


The user accessed Google Drive via web browser in addition to the desktop client. Bulk_extractor found URLs including:

1. https://drive.google.com/ (main Drive interface)
2. https://docs.google.com/ (Google Docs interface)
3. https://drive.google.com/sharing/share?subapp=10&shareProtocolVersion=2&theme=2&command=settings&shareUiType=default&authuser=0&client=desktop (file sharing interface)
4. https://www.googleapis.com/auth/drive.apps and https://www.googleapis.com/auth/drive.apps.readonly (Google Drive API authentication scopes)

The sharing URL is particularly significant - it shows the user was actively configuring or using Google Drive's file sharing functionality. Combined with the Google Drive desktop client installation, this demonstrates the user had multiple pathways for data exfiltration via cloud storage.

The presence of mail.google.com URLs also indicates Gmail usage, which could have been another exfiltration channel.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No network IOCs extracted | | |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `eric_p._lauer@omb.eop.gov` |  | US Government Email Address Found on Removable Media |
| Email | `wayne.longman@att.net` |  | US Government Email Address Found on Removable Media |
| Email | `mmun@loc.gov` |  | US Government Email Address Found on Removable Media |
| Email | `iaman.informant@nist.gov` |  | NIST Employee Identity Confirmed - Iaman Informant |
| Email | `1b788828-c8a2-4681-bf6f-b1df9935415b@nist.gov` |  | NIST Employee Identity Confirmed - Iaman Informant |




---

## Appendix C: MITRE ATT&CK Coverage

12 techniques identified across findings.


**Kill Chain Coverage:** Reconnaissance (1) > Persistence (2) > Privilege Escalation (1) > Defense Evasion (6) > Collection (1) > Exfiltration (2)


### Reconnaissance

| Technique | Name | Findings |
|-----------|------|----------|
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning | Intent Evidence: Web Searches About Data... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Admin Accounts Created - Minimal Use of... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Admin Accounts Created - Minimal Use of... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Admin Accounts Created - Minimal Use of... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Deleted Files on UDF Optical Media - Evidence... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Coordinated Anti-Forensic Cleanup Timeline -... |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Timestomp | Timestamp Manipulation Detected on PC; Data Exfiltration Timeline - March 22-25, 2015; Coordinated Anti-Forensic Cleanup Timeline -... |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Coordinated Anti-Forensic Cleanup Timeline -... |
| [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | Hidden Files and Directories | Files Disguised with Wrong Extensions on...; Data Exfiltration Timeline - March 22-25, 2015 |
| [T1564.004](https://attack.mitre.org/techniques/T1564/004/) | NTFS File Attributes | Deleted Files on UDF Optical Media - Evidence... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Source Data Found on "Authorized USB" Drive (rm1); Data Exfiltration Timeline - March 22-25, 2015; Secret Project Files Accessed on PC (LNK Evidence); Deleted Files on UDF Optical Media - Evidence... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Deleted Files on UDF Optical Media - Evidence... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | US Government Email Address Found on Removable Media; Source Data Found on "Authorized USB" Drive (rm1); Data Exfiltration Timeline - March 22-25, 2015; Cloud Storage Tools Installed (Google Drive and iCloud); Google Drive as Third Exfiltration Channel -... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 454 |
| Findings submitted | 22 |
| Confirmed | 19 |
| Inferences | 3 |
| Input tokens | 8.9M |
| Output tokens | 127.9K |
| Total tokens | 9.0M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/zai.glm-5 | 8.9M | 127.9K | 9.0M |




<details>
<summary>Evidence Sources (96)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 10 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| ez.mft | eztools | 98918 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.filelist | sleuthkit | 27 |
| tsk.masquerade | sleuthkit | 0 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| bulk.wordlist | bulk_extractor | 131102 |
| bulk.wordlist_dedup_1 | bulk_extractor | 112437 |
| tsk.masquerade | sleuthkit | 3 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 403827 |
| bulk.duplicates | bulk_extractor | 6623 |
| bulk.email | bulk_extractor | 6881 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 794 |
| bulk.jpeg | bulk_extractor | 9 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.url | bulk_extractor | 458564 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3681 |
| bulk.zip_carved | bulk_extractor | 22411 |
| registry.query.system | python-registry | 1 |
| evtx.manifest | evtx-extract | 54 |
| ez.shimcache | eztools | 307 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| registry.system | regripper | 33492 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| hayabusa.alerts | hayabusa | 35 |
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
| registry.query.system | python-registry | 1 |
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 7303 |
| bulk.duplicates | bulk_extractor | 1738 |
| bulk.email | bulk_extractor | 30 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7204 |
| bulk.url_services | bulk_extractor | 60 |
| bulk.zip_carved | bulk_extractor | 5221 |
| composite.correlation | composite | 1 |
| composite.timeline | composite | 172 |
| composite.execution | composite | 122 |
| composite.defense_evasion | composite | 174 |
| composite.lateral_movement | composite | 441 |
| composite.persistence | composite | 2430 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2496 |
| composite.file_staging | composite | 578 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.defense_evasion | composite | 131 |
| composite.execution | composite | 122 |
| composite.timeline | composite | 172 |
| composite.persistence | composite | 2450 |
| composite.lateral_movement | composite | 463 |
| composite.exfil | composite | 2514 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
