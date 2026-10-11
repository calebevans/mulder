# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T22:15:05.986717+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 117 evidence sources (43 disk, 74 other) | 1063 tool calls | 57 minutes
**Results:** 21 findings (2 critical, 11 high) | 21 confirmed, 0 inference | 1 hypothesis ruled out
**Timeline:** 2009-07-14 to 2015-03-25

**Key Threats:**
- Sensitive Secret Project files accessed and copied to removable media (RM1/RM2)
- Environment-Wide Multi-Vector Data Exfiltration Campaign Across PC and Three Removable Media

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-03-22 to 2015-03-24): User account manipulation - informant created additional admin accounts and reset passwords (+9 related)
- **Persistence** (2009-07-14 to 2015-03-23): Network environment and audit policy - corporate 10.11.11.0/24 network with file server 10.11.11.128; limited audit logging enabled (+2 related)
- **Command and Control** (2015-03-23 to 2015-03-24): Network share access to secured_drive containing Secret Project Data (+1 related)
- **Credential Access** (2015-03-22 to 2015-03-25): User identity: Iaman Informant with NIST government email and personal Gmail (+1 related)
- **Defense Evasion / Anti-Forensics** (2015-01-05 to 2015-03-24): Secret Project documents on optical disc authored by "company" with sensitive content (+2 related)
- **Other Activity** (2015-03-24): IOCs carved from optical disc reveal government email and reference URLs

**Tools:** search (446), get_raw_output (152), submit_finding (31), extract_optical_file (28), open_case (27). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Sensitive Secret Project files accessed and copied to removable media (RM1/RM2)** (2015-03-24T13:38:31Z to 2015-03-24T20:54:07Z)


- **Environment-Wide Multi-Vector Data Exfiltration Campaign Across PC and Three Removable Media** (2015-03-23T20:23:28Z to 2015-03-25T15:21:36Z)




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

1063 tool calls were executed across 31
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Insider Data Exfiltration — Case NDLC

## Background

This investigation concerns a suspected insider data theft incident involving a Windows 7 workstation (hostname: informant-PC, previously 37L4247F27-25) used by an employee identified as "Iaman Informant" with a NIST (National Institute of Standards and Technology) government email address (iaman.informant@nist.gov). The evidence set comprises four forensic disk images: the primary workstation (cfreds_2015_data_leakage_pc.E01), two USB flash drives (RM1 — "Authorized USB" exFAT volume, SanDisk Cruzer Fit SN 4C530012450531101593; RM2 — "IAMAN $_@" FAT32 volume, SanDisk Cruzer Fit SN 4C530012550531106501), and one optical disc (RM3 — "IAMAN CD", UDF multi-session write-once format). The investigation was conducted across 31 indexed evidence sources using 1063 tool invocations, producing 21 findings (2 critical, 11 high, 6 medium, 1 negative) mapped to 15 distinct MITRE ATT&CK techniques.

The workstation was connected to a corporate/government network segment (10.11.11.0/24) with a file server at 10.11.11.128 hosting a "secured_drive" network share containing a "Secret Project Data" folder. The system was configured with DHCP (assigned 10.11.11.129), default gateway 10.11.11.2, and DNS server 10.11.11.2. The audit policy on the system was notably limited: Object Access:File System auditing was disabled, and Process Creation auditing was also disabled, which significantly reduced the forensic trail available for reconstructing file access events.

## Incident Timeline

The incident unfolded over four days, from Sunday 2015-03-22 through Wednesday 2015-03-25, and can be organized into five distinct operational phases. All timestamps below are in UTC; local time was Eastern Daylight Time (UTC-4).

**Phase 1 — Account Provisioning and Environment Setup (2015-03-22):** The informant user account (RID 1000) was created at 14:33:54 UTC with password hint "IAMAN" and added to the Administrators group. Within the next 80 minutes, the informant created three additional local accounts: admin11 (RID 1001, created 15:51:54, added to Administrators, password reset 15:52:10), ITechTeam (RID 1002, created 15:52:30, added to Administrators, password reset 15:52:45), and temporary (RID 1003, created 15:53:01, limited account, password reset 15:53:11). The ITechTeam account was never used (Login Count: 0, Last Login: Never), constituting a dormant backdoor. The admin11 and temporary accounts were each logged into briefly (approximately 5 and 3 minutes respectively) for what appears to be access verification testing, then abandoned. During this same day, the informant installed Internet Explorer 11 from the D:\ optical drive, Google Chrome v.41.0.2272.101, and Microsoft Office 2013.

**Phase 2 — Research and Tool Acquisition (2015-03-22 to 2015-03-23):** Browser history and bulk extractor URL search analysis reveal extensive premeditation. The informant searched for "how to leak a secret," "leaking confidential information," "intellectual property theft," "data leakage methods," "anti-forensic tools" (85 hits), "CD burning method" (64 hits), "DLP DRM" (90 hits), "e-mail investigation" (88 hits), "Forensic Email Investigation" (78 hits), "what is windows system artifacts" (79 hits), "external device and forensics" (65 hits), "windows event logs" (61 hits), "eraser" (51 hits), and "ccleaner" (65 hits). On 2015-03-23 at 18:17:19 UTC, the informant visited forensicswiki.org/wiki/Anti-forensic_techniques and a DEFCON-20 presentation on Anti-Forensics. Later that evening, at 19:56:04 UTC, the informant searched for "google drive," visited google.com/drive, and downloaded both Google Drive and iCloud for Windows (icloudsetup.exe at 19:56:53 UTC). Google Drive was installed at 20:02:45 UTC, with the sync folder created at C:\Users\informant\Google Drive at 20:05:32 UTC.

**Phase 3 — Source Data Access (2015-03-23):** At 20:23:28 UTC, Shellbags record the informant accessing the network share \\10.11.11.128\secured_drive\Secret Project Data, which contained subfolders for Common Data, Past Projects, design, pricing decision, final, technical review, proposal, and progress. At 20:26 UTC, the informant opened (secret_project)_pricing_decision.xlsx in Excel. At 20:27 UTC, [secret_project]_final_meeting.pptx was opened in PowerPoint, and the V:\Secret Project Data\final folder was accessed. The informant also used Windows Search (WordWheelQuery) to search for "secret."

**Phase 4 — Multi-Vector Data Exfiltration (2015-03-24):** This was the most active day. At 13:38:00 UTC, the first USB device (RM1, SanDisk Cruzer Fit SN 4C530012450531101593) was connected, and Shellbags show access to E:\RM#1\Secret Project Data. The RM1 volume (labeled "Authorized USB," exFAT) contained Secret Project Data files including [secret_project]_design_concept.ppt, [secret_project]_detailed_design.pptx, [secret_project]_revised_points.ppt, [secret_project]_detailed_proposal.docx, and [secret_project]_proposal.docx. At 13:58:33 UTC, the second USB device (RM2, SanDisk Cruzer Fit SN 4C530012550531106501) was connected. On RM2 (labeled "IAMAN $_@," FAT32), 17 deleted files were recovered from $OrphanFiles, all created between 09:59:27 and 10:00:18 UTC, organized in folders matching the Secret Project Data structure (design, PRICIN~1, progress, proposal, TECHNI~1). Every file had a false extension: Office documents were disguised as media files (.jpg, .gif, .png, .avi, .amr, .svg, .txt, .zip, .7z, .one, .db). The volume label was changed to "IAMAN $_@" at 17:02:36 UTC. Later that evening, between 19:47 and 20:57 UTC, the informant staged and burned the "IAMAN CD" optical disc (RM3). Folders were created on D:\ with abbreviated names (de, tr, pd, prop, prog) matching Secret Project Data subfolders. The disc was burned using UDF write-once VAT format across 9 sessions, with files initially burned, then deleted and re-burned with folder name changes, ultimately leaving only 3 stock Windows sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) visible in the final session while 27 Secret Project files remained in deleted sessions. All 27 files on the disc were masqueraded with false extensions.

**Phase 5 — Anti-Forensic Cleanup and Departure (2015-03-25):** The informant's last login was at 10:45 UTC (10 total logins). At 14:47:40 UTC, Eraser 6.2.0.2962 was downloaded from SourceForge (eraser.heidi.ie). At 14:48:28 UTC, CCleaner 5.04 was downloaded from piriform.com. Eraser.exe was executed at 15:12:28 UTC, CCleaner64.exe at 15:15:50 UTC. The event log utility wevtutil.exe was also executed (Prefetch file WEVTUTIL.EXE-400D93E8.pf created 14:54:09 UTC), consistent with event log clearing. At 15:21:30 UTC, googledrivesync.exe was launched, initiating Google Drive synchronization. At 15:24:48 UTC, WINWORD.EXE was executed to create a resignation letter (Resignation_Letter_(Iaman_Informant).docx). The XPS version was viewed at 15:28:47 UTC, and RecentDocs was updated at 15:29:08 UTC. At 15:30:09 UTC, the informant accessed My Computer, apparently checking drives before departure.

## Key Findings

### Data Exfiltration — Removable Media

The investigation confirmed that sensitive "Secret Project Data" files were copied from the network share \\10.11.11.128\secured_drive to at least three physical media destinations. RM1 ("Authorized USB") contained Secret Project Data files in their original form. RM2 ("IAMAN $_@") contained 17 deleted files in $OrphanFiles with masqueraded extensions — Office documents renamed with media file extensions to conceal their true content. RM3 ("IAMAN CD") contained the same 17 masqueraded files plus additional deleted Secret Project files across 5 folders matching the network share structure, burned across 9 UDF sessions with a pattern of writing, deleting, and re-burning that left only innocuous stock images visible in the final session.

### Data Exfiltration — Cloud Storage

Google Drive was installed on 2015-03-23 and launched on 2015-03-25 at 15:21:30 UTC. The Google Drive sync folder was created at C:\Users\informant\Google Drive. Deleted sync databases (sync_config.db-shm, snapshot.db) suggest the sync configuration was subsequently cleaned up. iCloud for Windows was also downloaded but there is no direct evidence it was used for exfiltration. The Google Drive launch on the final day, immediately after anti-forensic tool execution and immediately before resignation letter creation, strongly suggests it was used as an exfiltration channel.

### Concealment — Extension Masquerading

All 27 files burned to the optical disc and all 17 deleted files on RM2 had false extensions that did not match their actual content type. ExifTool analysis confirmed every file was actually a ZIP-based Office document (docx, pptx, xlsx) or OLE compound file despite having extensions like .jpg, .png, .gif, .avi, .amr, .svg, .txt, .zip, .7z, .one, and .db. Specific examples include winter_storm.amr (actually OLE/PPT), winter_whether_advisory.zip (actually PPTX), my_favorite_cars.db (actually OLE), my_favorite_movies.7z (actually XLSX), a_gift_from_you.gif (actually DOCX, 35MB), and diary_#1d.txt through diary_#3p.txt (actually DOCX/PPTX/OLE). The diary files were actually Secret Project technical review documents. Steganography detection (stegdetect) and YARA malware scanning returned no positive results — the concealment was exclusively extension masquerading.

### Sensitive Content

The masqueraded documents contained "[secret_project]" in their titles, with metadata showing Author="company" and content related to "Scientific Data Stewardship," "ISCCP Data," "NCDC processing," "Polar Imager and Sounder," "Radar Rainfall Climatology," and "NEXRAD Data Volume." One document ([secret_project]_technical_review_#3) was 175 pages and 36,795 words. Bulk extractor carved an email address for Eric_P._Lauer@omb.eop.gov (Office of Management and Budget, Executive Office of the President) from the winter_whether_advisory.zip file, along with Washington DC phone number 202-395-7254 (associated with OMB). URLs embedded in documents included whitehouse.gov/omb references and digitalcorpora.org/corpora/govdocs links, confirming US government-related content.

### Anti-Forensic Activity

The informant downloaded and executed Eraser 6.2.0.2962 (secure deletion) and CCleaner 5.04 (system cleaning) on 2015-03-25. The event log utility wevtutil.exe was executed, consistent with event log clearing. Browser history shows prior research into anti-forensic techniques including visits to forensicswiki.org and a DEFCON-20 anti-forensics presentation. However, timestamp manipulation (timestomping) was specifically investigated and NOT detected — the timestomp detector flagged only a benign volume root artifact from image acquisition, and no user files showed evidence of timestamp manipulation.

### Account Manipulation and Persistence

The informant created three additional local accounts on 2015-03-22: admin11 and ITechTeam (both added to Administrators) and temporary (limited). The ITechTeam account was never used, constituting a dormant backdoor. The admin11 and temporary accounts were briefly tested and abandoned. This pattern is consistent with establishing multiple backdoor access vectors.

### Premeditation

Web search history provides overwhelming evidence of premeditation, with searches for data leakage methods, anti-forensic tools, CD burning methods, DLP/DRM, forensic investigation techniques, and evidence destruction conducted before and during the incident.

## Threat Intelligence and Attribution

This incident is attributed with high confidence to an insider threat — specifically the user "Iaman Informant" who operated the workstation informant-PC with a NIST government email address (iaman.informant@nist.gov). The evidence does not suggest an external threat actor; rather, it documents a deliberate, premeditated data theft by an authorized user with legitimate access to sensitive information.

The TTP profile is consistent with a knowledgeable insider with some technical sophistication: the actor researched anti-forensic techniques before acting, used multiple redundant exfiltration channels (two USB drives, one optical disc, cloud storage), employed extension masquerading to conceal document content, used anti-forensic tools (Eraser, CCleaner, wevtutil.exe) to clean traces, and created backdoor accounts for potential future access. However, the actor's operational security had gaps: the masquerading was detectable through file signature analysis, the deleted files on RM2 were recoverable from $OrphanFiles, the multi-session UDF burning pattern on RM3 preserved deleted content, and the browser history and registry artifacts provided a comprehensive activity trail despite the cleanup attempts.

The presence of NIST and OMB-related content in the exfiltrated documents, combined with the government email address, indicates this was a government insider threat incident involving sensitive scientific and technical data. The documents' content (climate data, radar systems, satellite imagery) suggests the data may have been related to government scientific research programs.

## Impact Assessment

The incident resulted in the confirmed exfiltration of sensitive "Secret Project Data" documents through at least four independent channels: two USB flash drives (RM1, RM2), one optical disc (RM3), and Google Drive cloud storage. The exfiltrated data included design documents, technical reviews (one 175 pages/36,795 words), pricing decisions, proposals, progress reports, and final meeting materials — representing a comprehensive theft of an entire project portfolio. The documents contained US government-related content including references to OMB (Office of Management and Budget) and scientific data stewardship programs.

The scope of compromise includes one workstation (informant-PC), one network share (\\10.11.11.128\secured_drive), and potentially the file server at 10.11.11.128. Three backdoor accounts were created (admin11, ITechTeam, temporary), with ITechTeam remaining as a dormant administrator account. The informant's NIST government email credentials and any data accessible through that account may also be at risk. The anti-forensic cleanup (Eraser, CCleaner, wevtutil.exe) may have destroyed additional evidence of the full scope of data accessed and exfiltrated. The limited audit policy (no file system auditing, no process creation auditing) further hampered the ability to determine the complete scope of data access.

## Immediate Tactical Containment

1. **Isolate the workstation informant-PC (10.11.11.129)** from the network immediately to prevent any further data access or remote connections.
2. **Disable all local accounts created by the informant:** admin11 (RID 1001), ITechTeam (RID 1002), and temporary (RID 1003). The ITechTeam account is a dormant administrator backdoor that must be disabled immediately.
3. **Disable the informant's NIST government email account** (iaman.informant@nist.gov) and all associated SMTP aliases (iaman@nist.gov, iaman@mail.nist.gov, iaman@nistgov.mail.onmicrosoft.com).
4. **Revoke the informant's access to the network share** \\10.11.11.128\secured_drive and audit all access to the Secret Project Data folder on file server 10.11.11.128.
5. **Block Google Drive synchronization** from the network perimeter and investigate whether any data was uploaded to the informant's Google Drive account. Preserve Google Drive sync logs and deleted database files (sync_config.db-shm, snapshot.db) from the workstation.
6. **Preserve the two USB devices** (SanDisk Cruzer Fit SN 4C530012450531101593 and SN 4C530012550531106501) and the optical disc ("IAMAN CD") as evidence. Do not allow these devices to be reused or destroyed.
7. **Preserve the workstation's event logs** immediately, as wevtutil.exe was executed and logs may have been cleared. Capture any remaining Security, System, and Application event logs before further degradation.
8. **Block the informant's personal Gmail** (iaman.informant.personal@gmail.com) from receiving any organizational data and investigate whether it was used for exfiltration.
9. **Initiate recovery of the informant's Google Drive account** through legal process to determine what data was uploaded.
10. **Notify OMB** (Eric_P._Lauer@omb.eop.gov, 202-395-7254) that documents containing OMB-related content were exfiltrated, as the data may include Executive Office of the President materials.

## Strategic Remediation

**Root Cause 1 — Absent Data Loss Prevention (DLP) controls enabled unrestricted removable media and cloud exfiltration.** The informant was able to connect two USB devices and burn an optical disc containing sensitive data without any blocking, alerting, or logging. The browser search history shows the informant specifically researched "DLP DRM" (90 hits) before acting, indicating awareness that DLP controls might be in place — and confirmation that they were not. Remediation: Deploy endpoint DLP controls that block or alert on writes to removable media containing classified or sensitive data patterns, block unauthorized cloud storage synchronization applications (Google Drive, iCloud), and alert on optical disc burning activity. This directly addresses the attack path documented in findings f_759908e2, f_3f802f8e, f_722a7716, and f_5253280b.

**Root Cause 2 — Insufficient audit logging prevented detection and hampered investigation.** The system's audit policy had Object Access:File System set to N (not audited) and Process Creation auditing disabled. This meant that file access to the Secret Project Data on the network share was not logged, and process execution was not recorded in event logs. The informant's research into "windows event logs" (61 hits) and "what is windows system artifacts" (79 hits) suggests awareness of logging gaps. Remediation: Enable Object Access auditing (File System, Removable Storage) and Process Creation auditing with command-line logging on all systems with access to sensitive data. Enable Audit Removable Storage policy to log USB device connections. This directly addresses the gap documented in finding f_3a4f5b73.

**Root Cause 3 — Unrestricted local administrator access enabled backdoor account creation.** The informant account was added to the Administrators group, which allowed creation of three additional accounts (admin11, ITechTeam, temporary) including two with administrator privileges. The ITechTeam dormant backdoor was never detected because there was no alerting on local account creation. Remediation: Implement alerting on Security event ID 4720 (account creation) and 4732 (member added to security-enabled local group), restrict local administrator group membership through Group Policy Restricted Groups, and implement LAPS (Local Administrator Password Solution) to manage local admin credentials. This directly addresses finding f_7e78eaed.

**Root Cause 4 — No network access control (NAC) or removable media policy allowed unauthorized USB devices.** Two personal SanDisk Cruzer Fit USB drives were connected to a government workstation and used to copy sensitive data without any device authorization or encryption requirements. Remediation: Implement a removable media policy that requires device authorization (whitelisting by serial number), enforces encryption on all removable media, and blocks unauthorized devices. The specific serial numbers 4C530012450531101593 and 4C530012550531106501 should be added to a blocklist. This directly addresses findings f_4546784e and f_759908e2.

**Root Cause 5 — No user behavior analytics (UBA) or insider threat program detected anomalous activity.** The informant's search history showed clear premeditation ("how to leak a secret," "anti-forensic tools," "data leakage methods") over multiple days, and the activity pattern (accessing sensitive data, connecting multiple USB devices, burning optical discs, installing cloud storage, downloading anti-forensic tools, creating a resignation letter) was highly anomalous. No alerts were generated. Remediation: Implement UBA controls that alert on combinations of: sensitive data access followed by removable media connection, anti-forensic tool downloads, cloud storage installation, and resignation letter creation. The specific search terms documented in finding f_b530a782 should be incorporated into insider threat detection rules.

**Root Cause 6 — Anti-forensic tool execution was not blocked or detected.** Eraser and CCleaner were downloaded from the internet and executed on a government workstation without any application whitelisting or blocking. The wevtutil.exe execution for event log clearing was similarly undetected. Remediation: Implement application whitelisting (e.g., AppLocker) to block unauthorized security/cleaning tools, and alert on execution of wevtutil.exe with clear/delete parameters. This directly addresses finding f_b9865aad.

## Conclusion

**Q1. What systems were compromised?** One workstation (informant-PC, 10.11.11.129) was the primary system from which data was exfiltrated. The network share on file server 10.11.11.128 (\\10.11.11.128\secured_drive) was the source of the stolen data. Three removable media devices (RM1 USB, RM2 USB, RM3 optical disc) received exfiltrated data. Google Drive cloud storage was used as an additional exfiltration channel.

**Q2. How did the attacker gain initial access?** This was an insider threat — the informant was an authorized user with legitimate access to the workstation and the network share containing Secret Project Data. No external intrusion occurred. The informant's account was created on 2015-03-22 and added to the Administrators group, providing full system access.

**Q3. What lateral movement occurred?** No traditional lateral movement was observed. The informant accessed the network share \\10.11.11.128\secured_drive from the workstation, which was a normal network operation for an authorized user. The informant also accessed a V:\ drive containing Secret Project Data. No evidence of remote desktop, PsExec, WMI, or other lateral movement techniques to other systems was found.

**Q4. What persistence mechanisms were installed?** Three backdoor local accounts were created: admin11 (Administrator, briefly tested), ITechTeam (Administrator, dormant — never used), and temporary (limited, briefly tested). The ITechTeam account represents the most significant persistence mechanism as a dormant administrator backdoor with a name chosen to blend in with legitimate IT staff accounts.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes, confirmed exfiltration of sensitive "Secret Project Data" occurred through four channels: (1) RM1 USB drive containing Secret Project files in original form; (2) RM2 USB drive containing 17 masqueraded Office documents (subsequently deleted); (3) RM3 optical disc containing 27 masqueraded Office documents across 5 folders matching the Secret Project Data structure, burned across 9 UDF sessions; (4) Google Drive cloud synchronization launched on the final day. The exfiltrated data included design documents, technical reviews (up to 175 pages/36,795 words), pricing decisions, proposals, progress reports, and final meeting materials — a comprehensive theft of an entire project portfolio containing US government-related content.

**Q6. What is the full timeline of the incident?** The incident spanned 2015-03-22 through 2015-03-25 (four days). Day 1 (03-22): Account creation, backdoor account provisioning, software installation (browsers, Office 2013). Day 2 (03-23): Anti-forensic research, cloud storage installation (Google Drive, iCloud), network share access, sensitive document access. Day 3 (03-24): USB device connections, data copying to RM1 and RM2, file masquerading, optical disc burning (RM3). Day 4 (03-25): Anti-forensic tool execution (Eraser, CCleaner, wevtutil.exe), Google Drive launch, resignation letter creation, final system access.

**Q7. What is the total scope and business impact?** The incident resulted in the theft of sensitive government scientific and technical data related to a "Secret Project" including climate data, radar systems, and satellite imagery research. The data was exfiltrated through four redundant channels, indicating the informant was determined to ensure successful removal of the data. The presence of OMB (Executive Office of the President) related content elevates the potential impact to national security. The anti-forensic cleanup may have obscured the full scope of data accessed. Three backdoor accounts remain on the system, and the informant's Google Drive account may contain additional stolen data.

**Q8. What are the recommended remediation actions?** Six strategic remediation actions are recommended, each addressing a specific root cause: (1) Deploy endpoint DLP to block removable media and cloud exfiltration; (2) Enable comprehensive audit logging (Object Access, Process Creation, Removable Storage); (3) Restrict local administrator access and implement account creation alerting; (4) Implement removable media device authorization and encryption policies; (5) Deploy user behavior analytics for insider threat detection; (6) Implement application whitelisting to block anti-forensic tools. Each recommendation is detailed in the Strategic Remediation section with specific references to findings and evidence from this case.


---

## Overview

| | |
|---|---|
| Findings | **21** (21 confirmed, 0 inference) |
| Severity | 2 critical, 11 high, 6 medium, 0 low, 2 info |
| Sources | 31 evidence sources across 1063 tool calls |
| Ruled Out | 1 hypotheses tested and rejected |


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
| 2009-07-14T04:45:41Z | Network environment and audit policy - corporate 10.11.11.0/24 network with file server 10.11.11.128; limited audit logging enabled | MEDIUM | registry.system, registry.security, registry.software |
| 2015-01-05T19:15:08Z | Secret Project documents on optical disc authored by "company" with sensitive content | HIGH | exiftool.metadata |
| 2015-03-22T14:33:54Z | User account manipulation - informant created additional admin accounts and reset passwords | HIGH | hayabusa.alerts, registry.sam |
| 2015-03-22T14:33:54Z | Timeline of data leakage activity (Eastern Standard Time) | HIGH | registry.ntuser.informant, registry.usrclass.informant, hayabusa.alerts, registry.sam, ez.shimcache, tsk.masquerade, registry.query.system |
| 2015-03-22T14:33:54Z | User identity: Iaman Informant with NIST government email and personal Gmail | INFO | bulk.email, registry.sam, bulk.domain |
| 2015-03-22T15:01:02Z | Installed software timeline - browsers, cloud storage, and anti-forensic tools | MEDIUM | registry.software, registry.system |
| 2015-03-22T15:51:54Z | Secondary backdoor accounts show brief usage patterns consistent with testing | MEDIUM | registry.ntuser.admin11, registry.usrclass.admin11, registry.ntuser.temporary, registry.usrclass.temporary, registry.sam |
| 2015-03-22T15:55:28Z | Web search history shows premeditation for data leakage and anti-forensics | HIGH | bulk.url_searches |
| 2015-03-23T18:17:19Z | Anti-forensic tools (Eraser, CCleaner) downloaded, installed, and executed | HIGH | ez.shimcache, registry.ntuser.informant, browser.history, bulk.url |
| 2015-03-23T18:31:10Z | USB device identification - Two SanDisk Cruzer Fit USB drives used for data exfiltration | MEDIUM | registry.system |
| 2015-03-23T19:56:04Z | Google Drive cloud storage installed and used for potential data exfiltration | HIGH | ez.shimcache, registry.ntuser.informant, browser.history, ez.mft, tsk.filelist, bulk.domain |
| 2015-03-23T20:23:28Z | Environment-Wide Multi-Vector Data Exfiltration Campaign Across PC and Three Removable Media | CRITICAL | registry.usrclass.informant, tsk.masquerade, optical.listing, exiftool.metadata, ez.mft, registry.system, ez.shimcache |
| 2015-03-23T20:23:28Z | Network share access to secured_drive containing Secret Project Data | HIGH | registry.usrclass.informant |
| 2015-03-24T09:59:27Z | Files masqueraded with false extensions on RM2 to conceal leaked documents | HIGH | tsk.masquerade, tsk.timeline, tsk.fsstat |
| 2015-03-24T13:38:31Z | Sensitive Secret Project files accessed and copied to removable media (RM1/RM2) | CRITICAL | registry.usrclass.informant, tsk.timeline, registry.ntuser.informant, tsk.filelist, tsk.fsstat |
| 2015-03-24T19:47:48Z | CD/DVD burning activity - BD-RE Drive (D:) used to burn "IAMAN CD" | HIGH | registry.ntuser.informant, registry.usrclass.informant, ez.shimcache |
| 2015-03-24T20:54:16Z | All 27 files on optical disc are masqueraded - Office documents disguised as media files | HIGH | exiftool.metadata, tsk.masquerade |
| 2015-03-24T20:54:16Z | RM3 Optical Disc (IAMAN CD) - Multi-session UDF with deleted Secret Project files | HIGH | optical.listing, hashdeep.hashes, exiftool.metadata |
| 2015-03-24T20:54:16Z | IOCs carved from optical disc reveal government email and reference URLs | MEDIUM | bulk.email, bulk.telephone, bulk.url, bulk.domain |
| 2015-03-24T20:54:16Z | No steganography or malware detected on optical disc - concealment via extension masquerading only | INFO | steg.detection, yara.files, exiftool.metadata |
| 2015-03-25T15:24:48Z | Resignation letter and XPS copy created before data exfiltration | MEDIUM | registry.ntuser.informant |




---

## Hypotheses Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No timestamp manipulation (timestomping) detected on user files** : Hypothesis: Given the user's documented anti-forensic research (forensicswiki.org anti-forensic techniques, DEFCON-20 anti-forensics presentation) and use of Eraser/CCleaner, timestamp...



---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Sensitive Secret Project files accessed and copied to removable media (RM1/RM2)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:38:31Z to 2015-03-24T20:54:07Z |
| **Sources** | registry.usrclass.informant, tsk.timeline, registry.ntuser.informant, tsk.filelist, tsk.fsstat |
| **Evidence Refs** | tc_38247814, tc_7ed2e324, tc_55c9dea8, tc_3bf236c6 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1030](https://attack.mitre.org/techniques/T1030/) |


User "informant" accessed sensitive "Secret Project" files from a network share (\\10.11.11.128\secured_drive\Secret Project Data) and copied them to at least two removable media devices. Shellbags show access to E:\RM#1\Secret Project Data and E:\Secret Project Data on 2015-03-24. The RM1 removable media (volume label "Authorized USB", exFAT) contained Secret Project Data files including [secret_project]_design_concept.ppt, [secret_project]_detailed_design.pptx, [secret_project]_revised_points.ppt, [secret_project]_detailed_proposal.docx, and [secret_project]_proposal.docx. The RM2 removable media (volume label "IAMAN $_@", FAT32) contained deleted files in $OrphanFiles with masqueraded extensions. RecentDocs shows access to [secret_project]_proposal.docx, [secret_project]_design_concept.ppt, [secret_project]_final_meeting.pptx, and (secret_project)_pricing_decision.xlsx. The user also searched for "secret" using Windows Search (WordWheelQuery).



### 2. [CRITICAL] Environment-Wide Multi-Vector Data Exfiltration Campaign Across PC and Three Removable Media

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:23:28Z to 2015-03-25T15:21:36Z |
| **Sources** | registry.usrclass.informant, tsk.masquerade, optical.listing, exiftool.metadata, ez.mft, registry.system, ez.shimcache |
| **Evidence Refs** | tc_38247814, tc_5557cc3a, tc_74edfdbd, tc_e0c26c57, tc_9273c310, tc_60481d4e, tc_28755812 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Cross-system correlation confirms a single coordinated insider data-theft campaign by user "informant" (Iaman Informant, NIST gov email) spanning the workstation (informant-PC) and three independent removable/cloud destinations, with the SAME set of "Secret Project Data" documents converging across all of them. Independent evidence sources converge: (1) PC registry Shellbags/RecentDocs show access to the source network share \\10.11.11.128\secured_drive\Secret Project Data and to E:\RM#1\Secret Project Data and E:\Secret Project Data; (2) RM1 USB ("Authorized USB", exFAT, SanDisk Cruzer Fit SN 4C530012450531101593) held Secret Project Data files; (3) RM2 USB ("IAMAN $_@", FAT32, SanDisk Cruzer Fit SN 4C530012550531106501) held 17 deleted Office documents masqueraded with media extensions in $OrphanFiles; (4) RM3 optical disc ("IAMAN CD", UDF multi-session VAT) held the SAME 17 masqueraded files plus 27 deleted Secret Project files across 5 folders matching the share structure (design, pricing decision, progress, proposal, technical review); (5) Google Drive cloud sync (googledrivesync.exe) launched 2015-03-25 15:21:30 UTC as a fourth exfiltration channel. Anti-forensic activity corroborated across sources: Eraser/CCleaner execution (ShimCache), and direct execution evidence of the event-log utility wevtutil.exe via its Prefetch file WEVTUTIL.EXE-400D93E8.pf created 2015-03-25 14:54:09 UTC (MFT), consistent with log clearing. The convergence of the identical masqueraded document set across two USB drives AND an optical disc, combined with cloud sync and anti-forensic tool execution, is more than the sum of individual artifacts and confirms deliberate, premeditated exfiltration of sensitive government (NIST/OMB-related) data through multiple redundant channels.



### 3. [HIGH] Files masqueraded with false extensions on RM2 to conceal leaked documents

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27Z to 2015-03-24T17:02:36Z |
| **Sources** | tsk.masquerade, tsk.timeline, tsk.fsstat |
| **Evidence Refs** | tc_5557cc3a, tc_7ed2e324, tc_3bf236c6 |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


On the RM2 removable media (FAT32, volume label "IAMAN $_@"), 17 deleted files were found in $OrphanFiles with extensions that did not match their actual content type. These were Office documents (docx, pptx, xlsx, ole) disguised as media files (jpg, gif, png, avi, amr, svg, txt, zip, 7z, one, db). Specific examples: winter_storm.amr (actually OLE/PPT), winter_whether_advisory.zip (actually PPTX), my_favorite_cars.db (actually OLE), my_favorite_movies.7z (actually XLSX), new_years_day.jpg (actually XLSX), super_bowl.avi (actually OLE), my_friends.svg (actually OLE), my_smartphone.png (actually DOCX), new_year_calendar.one (actually DOCX), a_gift_from_you.gif (actually DOCX, 35MB), landscape.png (actually DOCX), diary_#1d.txt through diary_#3p.txt (actually DOCX/PPTX/OLE). All were created on RM2 on 2015-03-24 between 09:59:27 and 10:00:18 UTC. These files were subsequently deleted. The masquerading was a deliberate concealment technique to disguise sensitive documents as innocuous media files.

Merged findings:
- Data staging and deletion on removable media RM2 (IAMAN volume): The RM2 removable media (FAT32, volume label "IAMAN $_@") shows evidence of data staging followed by deletion. Files were written to the device on 2015-03-24 between 09:59:27 and 10:00:18 UTC (creation times in $OrphanFiles), then subsequently deleted. The deleted files were organized in folders named: design, PRICIN~1 (pricing decision), progress, proposal, and TECHNI~1 (technical review) - matching the Secret Project Data folder structure from the network share. The files were masqueraded with false extensions. Additionally, the volume label was changed to "IAMAN $_@" on 2015-03-24 17:02:36 UTC, and a desktop.ini was created at 15:51:47 UTC. The RM2 device also contained deleted image files (bmp, gif, jpg, png, tif) that appear to be stock/sample images used as cover content alongside the masqueraded documents.



### 4. [HIGH] Anti-forensic tools (Eraser, CCleaner) downloaded, installed, and executed

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:17:19Z to 2015-03-25T15:15:50Z |
| **Sources** | ez.shimcache, registry.ntuser.informant, browser.history, bulk.url |
| **Evidence Refs** | tc_28755812, tc_55c9dea8, tc_ea4e2296, tc_cb9146d8 |
| **ATT&CK** | [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070.002](https://attack.mitre.org/techniques/T1070/002/) |


User "informant" downloaded and executed anti-forensic tools to cover tracks. Eraser 6.2.0.2962 was downloaded from SourceForge (eraser.heidi.ie) on 2015-03-25 14:47:40 UTC and executed at 15:12:28 UTC. CCleaner 5.04 was downloaded from piriform.com on 2015-03-25 14:48:28 UTC and executed at 15:15:50 UTC. Browser history shows the user searched for "anti-forensic tools" on Bing and visited forensicswiki.org/wiki/Anti-forensic_techniques and a DEFCON-20 presentation on Anti-Forensics on 2015-03-23 18:17:19 UTC. ShimCache confirms execution of Eraser.exe, CCleaner64.exe, and CCleaner.exe. The user also ran wevtutil.exe (event log utility) which can be used to clear event logs.



### 5. [HIGH] Google Drive cloud storage installed and used for potential data exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T19:56:04Z to 2015-03-25T15:21:36Z |
| **Sources** | ez.shimcache, registry.ntuser.informant, browser.history, ez.mft, tsk.filelist, bulk.domain |
| **Evidence Refs** | tc_28755812, tc_55c9dea8, tc_ea4e2296, tc_89c58183, tc_66b4aab5 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1102](https://attack.mitre.org/techniques/T1102/) |


User "informant" installed Google Drive on 2015-03-23 20:02 UTC and launched it on 2015-03-25 15:21:30 UTC. The Google Drive sync folder was created at C:\Users\informant\Google Drive (desktop.ini created 2015-03-23 20:05:32 UTC). Browser history shows the user searched for "google drive" and visited google.com/drive on 2015-03-23 19:56:04-08 UTC. iCloud for Windows was also downloaded (icloudsetup.exe) on 2015-03-23 19:56:53 UTC. The Google Drive application data shows deleted sync databases (sync_config.db-shm, snapshot.db in deleted state), suggesting the sync configuration was subsequently cleaned up. The user also had an Outlook profile configured with email iaman.informant@nist.gov (NIST government email), suggesting potential data exfiltration from a government system.



### 6. [HIGH] User account manipulation - informant created additional admin accounts and reset passwords

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54Z to 2015-03-22T15:53:11Z |
| **Sources** | hayabusa.alerts, registry.sam |
| **Evidence Refs** | tc_98465db3, tc_627d5719, tc_25628221, tc_13946dd4 |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1078](https://attack.mitre.org/techniques/T1078/) |


On 2015-03-22, user "informant" (RID 1000) performed extensive account manipulation: (1) Created account "admin11" (RID 1001) at 15:51:54 UTC and added it to Administrators group; (2) Created account "ITechTeam" (RID 1002) at 15:52:30 UTC and added it to Administrators group; (3) Created account "temporary" (RID 1003) at 15:53:01 UTC as a limited account; (4) Reset passwords for admin11 (15:52:10), ITechTeam (15:52:45), and temporary (15:53:11). The informant account itself was created on 2015-03-22 14:33:54 UTC with password hint "IAMAN" and was added to Administrators by WIN-D9RGPJQ68G8$ (system). The informant's password was also reset at creation time. This pattern of creating multiple admin accounts and resetting passwords is consistent with establishing backdoor access and preparing for data exfiltration activities.

Merged findings:
- ITechTeam dormant backdoor account - created with admin privileges but never used: The ITechTeam account (RID 1002) was created by user "informant" on 2015-03-22 15:52:30 UTC and added to the Administrators group. The password was reset at 15:52:45 UTC. However, the account has Login Count: 0 and Last Login Date: Never - it was never used to log into the system. This is a dormant backdoor account, created to provide persistent administrative access that could be used later without raising suspicion. The account name "ITechTeam" was likely chosen to blend in with legitimate IT staff accounts. The account was created during the same session as admin11 (15:51:54) and temporary (15:53:01), suggesting the informant was establishing multiple backdoor access vectors.



### 7. [HIGH] Network share access to secured_drive containing Secret Project Data

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T20:23:28Z to 2015-03-23T20:28:17Z |
| **Sources** | registry.usrclass.informant |
| **Evidence Refs** | tc_38247814 |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/), [T1030](https://attack.mitre.org/techniques/T1030/) |


Shellbags from user "informant" show access to network share \\10.11.11.128\secured_drive on 2015-03-23 20:23:28 UTC. The share contained a "Secret Project Data" folder with subfolders: Common Data, Past Projects, design, pricing decision, final, technical review, proposal, and progress. This was the source of the sensitive data that was subsequently copied to removable media. The network share was mapped/accessed before the data appeared on the removable drives. A V: drive also contained Secret Project Data (final subfolder), accessed on 2015-03-23 20:27:24 UTC.



### 8. [HIGH] Timeline of data leakage activity (Eastern Standard Time)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54Z to 2015-03-25T15:30:09Z |
| **Sources** | registry.ntuser.informant, registry.usrclass.informant, hayabusa.alerts, registry.sam, ez.shimcache, tsk.masquerade, registry.query.system |
| **Evidence Refs** | tc_55c9dea8, tc_38247814, tc_98465db3, tc_627d5719, tc_28755812, tc_5557cc3a, tc_98f8bd4c |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |


Complete timeline of the data leakage incident in system local timezone (Eastern Standard Time, UTC-4 during March 2015 EDT):

**2015-03-22 (Sunday):**
- 10:33 AM EDT: informant account created, added to Administrators
- 11:51 AM EDT: admin11 account created, added to Administrators, password reset
- 11:52 AM EDT: ITechTeam account created, added to Administrators, password reset
- 11:53 AM EDT: temporary account created, password reset
- 11:11 AM EDT: IE11 installer executed from D:\ (optical drive)
- 11:12 AM EDT: Chrome installed
- 3:03 PM EDT: Office 2013 installed

**2015-03-23 (Monday):**
- 2:17 PM EDT: Researched anti-forensic techniques (forensicswiki.org, DEFCON-20 PDF)
- 3:56 PM EDT: Downloaded Google Drive and iCloud installers
- 4:02 PM EDT: Google Drive installed
- 4:05 PM EDT: Google Drive folder created at C:\Users\informant\Google Drive
- 4:10 PM EDT: cmd.exe executed (4 times)
- 4:23 PM EDT: Accessed network share \\10.11.11.128\secured_drive\Secret Project Data
- 4:26 PM EDT: Opened (secret_project)_pricing_decision.xlsx in Excel
- 4:27 PM EDT: Opened [secret_project]_final_meeting.pptx in PowerPoint
- 4:27 PM EDT: Accessed V:\Secret Project Data\final folder

**2015-03-24 (Tuesday):**
- 9:38 AM EDT: Accessed E:\RM#1\Secret Project Data (USB drive RM1 connected)
- 9:59 AM EDT: Accessed E:\Secret Project Data subfolders
- 10:01 AM EDT: Opened winter_whether_advisory.zip from E:\Secret Project Data\design
- 5:59 AM EDT: Masqueraded files created on RM2 (IAMAN volume) - files written between 5:59-6:00 AM EDT
- 3:47 PM EDT: D:\ drive folders created (de, tr, pd, prop, prog) - CD/DVD burning staging
- 3:54 PM EDT: winter_whether_advisory.zip accessed on D:\de\
- 4:44 PM EDT: winter_whether_advisory.zip opened from D:\de\
- 4:54 PM EDT: Accessed E:\Secret Project Data\progress
- 1:02 PM EDT: Volume label on RM2 changed to "IAMAN $_@"

**2015-03-25 (Wednesday):**
- 10:45 AM EDT: informant last login (10 logins total)
- 10:47 AM EDT: Eraser 6.2.0.2962.exe downloaded and executed
- 10:48 AM EDT: ccsetup504.exe (CCleaner) downloaded and executed
- 10:50 AM EDT: Eraser installer .NET Framework setup executed
- 11:12 AM EDT: Eraser.exe executed
- 11:15 AM EDT: CCleaner64.exe executed
- 11:21 AM EDT: googledrivesync.exe launched
- 11:24 AM EDT: WINWORD.EXE executed (4 times) - resignation letter
- 11:28 AM EDT: Resignation_Letter_(Iaman_Informant).xps viewed
- 11:29 AM EDT: RecentDocs updated with Resignation_Letter_(Iaman_Informant).docx
- 11:30 AM EDT: My Computer accessed (checking drives)



### 9. [HIGH] CD/DVD burning activity - BD-RE Drive (D:) used to burn "IAMAN CD"

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T19:47:48Z to 2015-03-24T20:44:18Z |
| **Sources** | registry.ntuser.informant, registry.usrclass.informant, ez.shimcache |
| **Evidence Refs** | tc_55c9dea8, tc_38247814, tc_28755812 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1030](https://attack.mitre.org/techniques/T1030/) |


RecentDocs shows access to "BD-RE Drive (D:) IAMAN CD" and "BD-RE Drive (D:)" on 2015-03-24, indicating the user burned a Blu-ray RE writable disc labeled "IAMAN CD". Shellbags show folders created on D:\ drive (de, tr, pd, prop, prog) on 2015-03-24 19:47-20:41 UTC, which are abbreviated folder names matching Secret Project Data subfolders (de=design, tr=technical review, pd=pricing decision, prop=proposal, prog=progress). The winter_whether_advisory.zip file was accessed on D:\de\ at 19:54:43 UTC. The ShimCache also shows IE11 installer was present on D:\ drive. This represents a third exfiltration vector beyond the USB drives and cloud storage.



### 10. [HIGH] All 27 files on optical disc are masqueraded - Office documents disguised as media files

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:55:46Z |
| **Sources** | exiftool.metadata, tsk.masquerade |
| **Evidence Refs** | tc_e0c26c57, tc_abb35244 |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1027](https://attack.mitre.org/techniques/T1027/) |


Every single file burned to the "IAMAN CD" optical disc has a false extension that does not match its actual content type. ExifTool analysis reveals all files are actually ZIP-based Office documents (docx, pptx, xlsx) or OLE compound files, despite having extensions like .jpg, .png, .gif, .avi, .amr, .svg, .txt, .zip, .7z, .one, and .db. Specific masquerading: winter_storm.amr (OLE/PPT), winter_whether_advisory.zip (PPTX), my_favorite_cars.db (OLE), my_favorite_movies.7z (XLSX), new_years_day.jpg (XLSX), super_bowl.avi (OLE), my_friends.svg (OLE), my_smartphone.png (DOCX), new_year_calendar.one (DOCX), a_gift_from_you.gif (DOCX, 35MB), landscape.png (DOCX), diary_#1d.txt through diary_#3p.txt (DOCX/PPTX/OLE). The diary files are actually Secret Project technical review documents. This is a deliberate concealment technique to disguise sensitive documents as innocuous media files.



### 11. [HIGH] Secret Project documents on optical disc authored by "company" with sensitive content

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-05T19:15:08Z to 2015-01-20T20:05:00Z |
| **Sources** | exiftool.metadata |
| **Evidence Refs** | tc_e0c26c57, tc_725629fb |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1030](https://attack.mitre.org/techniques/T1030/) |


The masqueraded files on the optical disc are Microsoft Office documents containing "[secret_project]" in their titles. Metadata analysis reveals: diary_#1p.txt and diary_#3p.txt are PowerPoint presentations titled "[secret_project]_technical_review_#3" and "[secret_project]_technical_review_#2"; diary_#3d.txt is a Word document titled "[secret_project]_technical_review_#3" with 175 pages and 36,795 words. All documents have Author="company", Last Modified By="company", and Current User="company". The PowerPoint files contain embedded content about "Scientific Data Stewardship", "ISCCP Data", "NCDC processing", "Polar Imager and Sounder", "Radar Rainfall Climatology", and "NEXRAD Data Volume" - suggesting government/scientific data. The documents contain hyperlinks to digitalcorpora.org/corpora/govdocs and hdl.loc.gov. Create dates range from 2001-2003 (original templates) with modify dates in January 2015, indicating these are legitimate sensitive documents that were copied and disguised.



### 12. [HIGH] RM3 Optical Disc (IAMAN CD) - Multi-session UDF with deleted Secret Project files

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z |
| **Sources** | optical.listing, hashdeep.hashes, exiftool.metadata |
| **Evidence Refs** | tc_5bfffcd4, tc_5a09683b, tc_02ac902a, tc_74edfdbd, tc_64408059 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1030](https://attack.mitre.org/techniques/T1030/) |


The RM3 optical disc (volume label "IAMAN CD", UDF write-once with VAT) contains 9 sessions showing a pattern of file writing and deletion. The disc contains:
- 3 cover images (Koala.jpg, Penguins.jpg, Tulips.jpg) - standard Windows sample images used as decoys
- 5 folders matching Secret Project Data structure: design, pricing decision, progress, proposal, technical review
- 17 masqueraded files (same as RM2) with false extensions hiding Office documents
- Files were written in session 0, then deleted in subsequent sessions (sessions -1 through -7)
- The UDF VAT (Virtual Allocation Table) shows 9 generations, indicating the disc was written multiple times with files being added and removed
- ExifTool confirms the masqueraded files are actually Office documents (ZIP/DOCX/PPT/DOC format)
- The PPT files have titles confirming Secret Project content: "[secret_project]_technical_review_#3" and "[secret_project]_technical_review_#2"
- The DOC file is "[secret_project]_technical_review_#3" - 175 pages, 36,795 words
- The disc was created on 2015-03-24 between 20:54:16 and 20:57:03 UTC
- This represents a third exfiltration vector beyond the USB drives (RM1, RM2) and cloud storage (Google Drive)

Merged findings:
- Optical disc "IAMAN CD" contains 9 burn sessions with deleted Secret Project files: The rm3 optical disc (UDF write-once VAT format, volume label "IAMAN CD", 52,513 sectors) contains 9 sessions (VAT generations) showing a pattern of burning, deleting, and re-burning files. The disc contains 3 present image files (Koala.jpg, Penguins.jpg, Tulips.jpg - stock Windows sample images from 2008-2009) and 27 deleted files across 5 directories matching Secret Project Data folder names: /design (de), /pricing decision (pd), /progress (prog), /proposal (prop), /technical review (tr). All deleted files were created on 2015-03-24 between 20:54:16 and 20:55:46 UTC. The files were initially burned with full directory names (session 0), then deleted and re-burned with abbreviated names (sessions -1 through -7), suggesting an attempt to obscure the content or fit within naming constraints.
- Multi-session burning pattern shows deliberate file management on optical disc: The "IAMAN CD" optical disc uses UDF write-once VAT (Virtual Allocation Table) format with 9 sessions, showing a sophisticated burning pattern. Session 0 (the final visible session) contains only 3 stock image files (Koala.jpg, Penguins.jpg, Tulips.jpg) and 10 deleted directory entries. Sessions -1 through -7 contain the actual Secret Project files, organized in folders with abbreviated names (de, pd, prog, prop, tr) that were later renamed to full names (design, pricing decision, progress, proposal, technical review). This pattern indicates: (1) Files were initially burned with abbreviated folder names; (2) Multiple burn sessions were used to add files incrementally; (3) Folder names were changed between sessions; (4) All sensitive files were marked as deleted in the final session, leaving only innocuous stock images visible. This is consistent with an attempt to create a disc that appears to contain only personal photos while actually containing hidden sensitive documents.



### 13. [HIGH] Web search history shows premeditation for data leakage and anti-forensics

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:55:28Z to 2015-03-23T20:05:35Z |
| **Sources** | bulk.url_searches |
| **Evidence Refs** | tc_6014173f, tc_a9077d8f |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Bulk extractor URL search history from the PC shows the user conducted extensive research before and during the data leakage incident, demonstrating clear premeditation. Key searches include:
- "how to leak a secret" (multiple variations)
- "leaking confidential information"
- "intellectual property theft"
- "data leakage methods"
- "information leakage cases"
- "anti-forensic tools" (85 hits)
- "anti-forensics" (multiple variations)
- "CD burning method" (64 hits) and "CD burning method in windows" (53 hits)
- "how to delete data" (multiple variations)
- "data recovery tools" (multiple variations)
- "cloud storage" (multiple variations)
- "system cleaner" (multiple variations)
- "security checkpoint cd-r"
- "DLP DRM" (90 hits) - Data Loss Prevention
- "e-mail investigation" (88 hits)
- "Forensic Email Investigation" (78 hits)
- "what is windows system artifacts" (79 hits)
- "external device and forensics" (65 hits)
- "investigation on windows machine" (64 hits)
- "windows event logs" (61 hits)
- "eraser" (51 hits)
- "ccleaner" (65 hits)
- "google drive" (10 hits)
- "apple icloud"
- "outlook 2013 settings"
- "file sharing and tethering" (491 hits)
- "digital forensics" (1 hit)
These searches show the user was researching how to leak data, cover their tracks, and understand forensic investigation techniques before executing the data theft.

Merged findings:
- Extensive research into data leakage, anti-forensics, and evidence destruction techniques: Bulk extractor URL search histogram from the main disk (cfreds_2015_data_leakage_pc.E01) reveals the user conducted extensive research into data leakage and anti-forensic techniques. Search queries found in browser data include: "anti-forensic tools" (85 hits), "ccleaner" (65 hits), "eraser" (51 hits), "cd burning method" (64 hits), "cd burning method in windows" (53 hits), "windows event logs" (61 hits), "DLP DRM" (90 hits), "e-mail investigation" (88 hits), "Forensic Email Investigation" (78 hits), "external device and forensics" (65 hits), "investigation on windows machine" (64 hits), "what is windows system artifacts" (79 hits), "information leakage cases" (47 hits), "leaking confidential information" (2 hits), "how to leak a secret" (6 hits), "intellectual property theft" (6 hits), "cloud storage" (6 hits), "how to delete data" (5 hits), "system cleaner" (5 hits), "data recovery tools" (3 hits), "digital forensics" (1 hit), "data leakage methods" (1 hit), "security checkpoint cd-r" (1 hit), "file sharing and tethering" (491 hits), "google drive" (10 hits), "apple icloud" (1 hit), and "outlook 2013 settings" (1 hit). These searches demonstrate premeditation and deliberate planning for data exfiltration and evidence destruction.



### 14. [MEDIUM] Resignation letter and XPS copy created before data exfiltration

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T15:24:48Z to 2015-03-25T15:29:08Z |
| **Sources** | registry.ntuser.informant |
| **Evidence Refs** | tc_55c9dea8 |


User "informant" created a resignation letter (Resignation_Letter_(Iaman_Informant).docx) and saved it as both DOCX and XPS format on 2015-03-25. The document appears in RecentDocs with LastWrite 2015-03-25 15:29:08 UTC, and in OpenSavePidlMRU showing it was saved via WINWORD.EXE. The XPS version was viewed with xpsrchvw.exe at 15:28:47 UTC. This indicates the user was preparing to leave the organization, which is a common precursor to insider data theft. The resignation letter was created on the same day as the anti-forensic tool execution (Eraser at 15:12:28, CCleaner at 15:15:50) and Google Drive launch (15:21:30), suggesting a coordinated sequence of: resign → clean traces → exfiltrate via cloud → leave.



### 15. [MEDIUM] IOCs carved from optical disc reveal government email and reference URLs

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z |
| **Sources** | bulk.email, bulk.telephone, bulk.url, bulk.domain |
| **Evidence Refs** | tc_926ea060, tc_57a83d43, tc_2aa5dd96 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Bulk extractor analysis of the rm3 optical disc ("IAMAN CD") carved the following IOCs: (1) Email: Eric_P._Lauer@omb.eop.gov (Office of Management and Budget, Executive Office of the President) - found in the winter_whether_advisory.zip file which is actually a PowerPoint presentation; (2) Telephone numbers: 202-395-7254 (Washington DC area code, associated with OMB), (760) 413-4114 (California), 206-526-6653 (Seattle WA); (3) URLs embedded in documents: http://www.iec.ch (International Electrotechnical Commission), http://www.whitehouse.gov/omb/egov/documents/FEA_CRM_v23_Final_Oct_2007.pdf, http://www.whitehouse.gov/omb/circulars/a11/current_year/s53.pdf, http://digitalcorpora.org/corpora/govdocs, http://hdl.loc.gov/loc.pnp/acd.2a10339, plus numerous Microsoft schema URLs from Office document XML. The presence of OMB (White House) email and URLs confirms the documents contain US government-related content. The digitalcorpora.org URLs are from the GovDocs corpus, suggesting these may be reference documents embedded within the Secret Project files.



### 16. [MEDIUM] USB device identification - Two SanDisk Cruzer Fit USB drives used for data exfiltration

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:31:10Z to 2015-03-24T13:58:33Z |
| **Sources** | registry.system |
| **Evidence Refs** | tc_60481d4e, tc_84d0224a, tc_a9fa6b01, tc_45f07e20 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Registry USBSTOR key shows two SanDisk Cruzer Fit USB devices were connected to the system:
1. Serial number 4C530012450531101593 (last written 2015-03-24 13:38:00 UTC) - This corresponds to RM1 ("Authorized USB" volume label)
2. Serial number 4C530012550531106501 (last written 2015-03-24 13:58:33 UTC) - This corresponds to RM2 ("IAMAN $_@" volume label)
Both devices are SanDisk Cruzer Fit USB flash drives (Rev 2.01). The first device was last connected on 2015-03-24 at 13:38:00 UTC, and the second on 2015-03-24 at 13:58:33 UTC. These timestamps align with the Shellbags evidence showing access to E:\RM#1\Secret Project Data and E:\Secret Project Data on 2015-03-24. The USBSTOR key was last written on 2015-03-23 18:31:10 UTC, indicating the first USB device was connected on that date.



### 17. [MEDIUM] Network environment and audit policy - corporate 10.11.11.0/24 network with file server 10.11.11.128; limited audit logging enabled

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2009-07-14T04:45:41Z to 2015-03-25T15:19:50Z |
| **Sources** | registry.system, registry.security, registry.software |
| **Evidence Refs** | tc_298e2641, tc_9890d351, tc_195b979a, tc_c1248c69, tc_18847905 |
| **ATT&CK** | [T1562.002](https://attack.mitre.org/techniques/T1562/002/) |


Registry analysis of the SYSTEM hive shows the network interface was configured with DHCP enabled and received an IP address on the 10.11.11.x subnet (DhcpIPAddress = 10.11.11.x, truncated in output). The network share accessed by the user (\\10.11.11.128\secured_drive) was on the same subnet, indicating the system was on a corporate/internal network. The LastLoggedOnUser was .\informant (informant-PC\informant), confirming the informant account was the last user logged in before the system was imaged. The system hostname was informant-PC (previously 37L4247F27-25 before renaming). The audit policy from the Security hive shows limited logging was enabled - Object Access:File System was set to N (not audited), meaning file access to the Secret Project Data was not being logged. Process Creation auditing was also disabled (N). This limited audit policy may have facilitated the data theft by reducing the forensic trail.

Network environment detail (merged from f_99232d8a): The system was connected to a corporate network with IP Address 10.11.11.129 (DHCP assigned), Subnet Mask 255.255.255.0, Default Gateway 10.11.11.2, DNS Server 10.11.11.2, DHCP Server 10.11.11.254, Domain localdomain. File Server 10.11.11.128 hosted the secured_drive share with Secret Project Data. Timezone: Eastern Standard Time (UTC-5, EDT UTC-4 during March 2015). DHCP Lease obtained 2015-03-25 10:33:18 UTC (LeaseObtainedTime 1427296790). The network interface {E2B9AEEC-B1F7-4778-A049-50D7F2DAB2DE} was the active connection. This was a corporate/government network environment, consistent with the NIST email addresses found on the system.



### 18. [MEDIUM] Installed software timeline - browsers, cloud storage, and anti-forensic tools

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:01:02Z to 2015-03-23T20:02:45Z |
| **Sources** | registry.software, registry.system |
| **Evidence Refs** | tc_59433ce3, tc_fdd1328e |


Registry software hive shows the following software was installed on the system during the incident timeframe:
- 2015-03-22 15:11:51 UTC: Google Chrome v.41.0.2272.101 installed
- 2015-03-22 15:16:03 UTC: Google Update Helper v.1.3.26.9 installed
- 2015-03-22 15:01:02 UTC: Microsoft Office 2013 (Excel, Access, etc.) installed
- 2015-03-23 20:00:45 UTC: Apple Application Support v.3.0.6 installed (part of iCloud installation)
- 2015-03-23 20:01:01 UTC: Apple Software Update v.2.1.3.127 installed (part of iCloud installation)
- 2015-03-23 20:00:56 UTC: Bonjour Service installed (part of iCloud installation, runs as mDNSResponder.exe)
- 2015-03-23 20:02:45 UTC: Google Drive installed (googledrivesync64.dll registered)
The installation timeline shows the user installed browsers (Chrome), cloud storage (Google Drive, iCloud), and productivity software (Office 2013) in preparation for the data leakage. The iCloud installation (Apple Application Support, Apple Software Update, Bonjour) was downloaded on 2015-03-23 19:56:53 UTC and installed around 20:00-20:01 UTC, just before the network share access at 20:23 UTC.



### 19. [MEDIUM] Secondary backdoor accounts show brief usage patterns consistent with testing

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:51:54Z to 2015-03-22T15:57:31Z |
| **Sources** | registry.ntuser.admin11, registry.usrclass.admin11, registry.ntuser.temporary, registry.usrclass.temporary, registry.sam |
| **Evidence Refs** | tc_ae1d8fbf, tc_61db37a8, tc_ea0c5b61, tc_9cc6e931, tc_25628221 |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |


The admin11 and temporary accounts created by informant show brief usage patterns consistent with testing the accounts before abandoning them:

**admin11 (RID 1001):**
- Created 2015-03-22 15:51:54 UTC, added to Administrators
- Logged in twice (Login Count: 2), last login 2015-03-22 15:57:02 UTC
- UserAssist shows: NOTEPAD.EXE (1 run), explorer.exe (1 run), Chrome (1 run)
- RecentDocs shows access to setupapi.dev.log and inf folder
- Shellbags show navigation to C:\Windows\inf\ServiceModelEndpoint 3.0.0.0
- TypedURLs shows only the default IE first-run URL
- No WordWheelQuery searches, no ComDlg32 history
- Activity lasted approximately 5 minutes (15:52-15:57)

**temporary (RID 1003):**
- Created 2015-03-22 15:53:01 UTC as limited account
- Logged in once (Login Count: 1), last login 2015-03-22 15:55:57 UTC
- UserAssist shows: explorer.exe (1 run)
- Shellbags show navigation to C:\Users\temporary\Downloads and Control Panel\User Accounts\Change Your Password
- TypedURLs shows only the default IE first-run URL
- No RecentDocs, no WordWheelQuery searches
- Activity lasted approximately 3 minutes (15:54-15:57)

Both accounts were used briefly and then abandoned. The admin11 account was used to check system setup files (setupapi.dev.log, inf folder), possibly to verify the account had proper admin access. The temporary account was used to access User Accounts control panel, possibly to verify password change functionality. Neither account was used for any data access or exfiltration activities.



### 20. [INFO] User identity: Iaman Informant with NIST government email and personal Gmail

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54Z |
| **Sources** | bulk.email, registry.sam, bulk.domain |
| **Evidence Refs** | tc_d210694c, tc_627d5719, tc_66b4aab5 |


The primary user of the PC is "informant" (Iaman Informant), with Windows account created 2015-03-22 14:33:54 UTC and password hint "IAMAN". The user had an Outlook profile configured with government email iaman.informant@nist.gov (NIST - National Institute of Standards and Technology), with SMTP addresses iaman@nist.gov, iaman@mail.nist.gov, and iaman@nistgov.mail.onmicrosoft.com. A personal Gmail account was also found: iaman.informant.personal@gmail.com. The user also had cookies from eraser.heidi.ie (informant@heidi.ie) and sourceforge.net (informant@sourceforge.net), linking the user to the anti-forensic tool downloads. The email addresses and Outlook OST file confirm this was a government workstation used by an insider who leaked sensitive data.



### 21. [INFO] No steganography or malware detected on optical disc - concealment via extension masquerading only

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z |
| **Sources** | steg.detection, yara.files, exiftool.metadata |
| **Evidence Refs** | tc_53cd40a2, tc_d804b917, tc_e0c26c57 |


Steganography detection (stegdetect) and YARA malware scanning of all extracted files from the rm3 optical disc returned no positive results. The concealment technique used was exclusively extension masquerading (renaming Office documents with media file extensions) rather than steganographic embedding or malware. The three present image files (Koala.jpg, Penguins.jpg, Tulips.jpg) are legitimate Windows sample images with valid JPEG signatures and Corbis/Microsoft copyright metadata from 2008-2009, likely included as cover content to make the disc appear to contain only innocuous photos.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | Sensitive Secret Project files accessed and copied to removable media (RM1/RM2) |
| Internal IP | `10.11.11.129` |  | Network environment and audit policy - corporate 10.11.11.0/24 network with file |
| Internal IP | `10.11.11.2` |  | Network environment and audit policy - corporate 10.11.11.0/24 network with file |
| Internal IP | `10.11.11.254` |  | Network environment and audit policy - corporate 10.11.11.0/24 network with file |
| External IP | `1.3.26.9` |  | Installed software timeline - browsers, cloud storage, and anti-forensic tools |
| External IP | `2.1.3.127` |  | Installed software timeline - browsers, cloud storage, and anti-forensic tools |
| External IP | `3.0.0.0` |  | Secondary backdoor accounts show brief usage patterns consistent with testing |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Users\informant\Google` |  | Google Drive cloud storage installed and used for potential data exfiltration |
| Path | `C:\Windows\inf\ServiceModelEndpoint` |  | Secondary backdoor accounts show brief usage patterns consistent with testing |
| Path | `C:\Users\temporary\Downloads` |  | Secondary backdoor accounts show brief usage patterns consistent with testing |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `iaman.informant@nist.gov` |  | Google Drive cloud storage installed and used for potential data exfiltration |
| Email | `eric_p._lauer@omb.eop.gov` |  | IOCs carved from optical disc reveal government email and reference URLs |




---

## Appendix C: MITRE ATT&CK Coverage

15 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (3) > Privilege Escalation (2) > Defense Evasion (7) > Collection (2) > Command and Control (1) > Exfiltration (3)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account manipulation - informant created...; Secondary backdoor accounts show brief usage... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account manipulation - informant created...; Secondary backdoor accounts show brief usage... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | User account manipulation - informant created... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | User account manipulation - informant created...; Timeline of data leakage activity (Eastern...; Secondary backdoor accounts show brief usage... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account manipulation - informant created...; Secondary backdoor accounts show brief usage... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | User account manipulation - informant created... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Files masqueraded with false extensions on RM2...; All 27 files on optical disc are masqueraded -...; RM3 Optical Disc (IAMAN CD) - Multi-session... |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Resource Name or Location | Files masqueraded with false extensions on RM2...; Timeline of data leakage activity (Eastern...; All 27 files on optical disc are masqueraded -...; RM3 Optical Disc (IAMAN CD) - Multi-session...; Web search history shows premeditation for...; Environment-Wide Multi-Vector Data... |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Anti-forensic tools (Eraser, CCleaner)...; Timeline of data leakage activity (Eastern...; Web search history shows premeditation for...; Environment-Wide Multi-Vector Data... |
| [T1070.002](https://attack.mitre.org/techniques/T1070/002/) | Clear Linux or Mac System Logs | Anti-forensic tools (Eraser, CCleaner)... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Files masqueraded with false extensions on RM2...; Anti-forensic tools (Eraser, CCleaner)... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User account manipulation - informant created...; Secondary backdoor accounts show brief usage... |
| [T1562.002](https://attack.mitre.org/techniques/T1562/002/) | Disable Windows Event Logging | Network environment and audit policy -... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network share access to secured_drive... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Files masqueraded with false extensions on RM2...; Environment-Wide Multi-Vector Data... |


### Command and Control

| Technique | Name | Findings |
|-----------|------|----------|
| [T1102](https://attack.mitre.org/techniques/T1102/) | Web Service | Google Drive cloud storage installed and used... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1030](https://attack.mitre.org/techniques/T1030/) | Data Transfer Size Limits | Sensitive Secret Project files accessed and...; Network share access to secured_drive...; CD/DVD burning activity - BD-RE Drive (D:)...; Secret Project documents on optical disc...; RM3 Optical Disc (IAMAN CD) - Multi-session... |
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Sensitive Secret Project files accessed and...; Timeline of data leakage activity (Eastern...; CD/DVD burning activity - BD-RE Drive (D:)...; Secret Project documents on optical disc...; IOCs carved from optical disc reveal...; RM3 Optical Disc (IAMAN CD) - Multi-session...; Web search history shows premeditation for...; USB device identification - Two SanDisk Cruzer...; Environment-Wide Multi-Vector Data... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Google Drive cloud storage installed and used...; Timeline of data leakage activity (Eastern...; Web search history shows premeditation for...; Environment-Wide Multi-Vector Data... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 1063 |
| Findings submitted | 21 |
| Confirmed | 21 |
| Inferences | 0 |
| Input tokens | 4.1K |
| Output tokens | 163.4K |
| Total tokens | 167.4K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/us.moonshotai.kimi-k3 | 4.1K | 163.4K | 167.4K |




<details>
<summary>Evidence Sources (117)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 10 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.partitions | sleuthkit | 9 |
| tsk.fsstat | sleuthkit | 40 |
| tsk.timeline | sleuthkit | 187 |
| tsk.partitions | sleuthkit | 8 |
| tsk.fsstat | sleuthkit | 37 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.timeline | sleuthkit | 67 |
| tsk.filelist | sleuthkit | 27 |
| tsk.masquerade | sleuthkit | 0 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| strings.output | strings | 22065 |
| tsk.filelist | sleuthkit | 51 |
| browser.history | browser_parser | 251 |
| browser.history | browser_parser | 251 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 366963 |
| bulk.duplicates | bulk_extractor | 12 |
| bulk.email | bulk_extractor | 6851 |
| bulk.ether | bulk_extractor | 6 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.url | bulk_extractor | 421750 |
| exiftool.metadata | exiftool | 9 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| tsk.masquerade | sleuthkit | 3 |
| ez.mft | eztools | 98918 |
| evtx.manifest | evtx-extract | 54 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| ez.shimcache | eztools | 307 |
| browser.history | browser_parser | 251 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| registry.software | regripper | 33492 |
| registry.software | regripper | 283 |
| registry.software | regripper | 283 |
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
| optical.listing | mulder-optical | 58 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.telephone | bulk_extractor | 8 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| hashdeep.hashes | hashdeep | 32 |
| exiftool.metadata | exiftool | 770 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| browser.history | browser_parser | 251 |
| composite.file_staging | composite | 578 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.timeline | composite | 172 |
| composite.execution | composite | 122 |
| composite.defense_evasion | composite | 163 |
| enrichment.iocs | enrichment | 67 |
| composite.lateral_movement | composite | 379 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.persistence | composite | 2418 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2516 |
| composite.correlation | composite | 1 |
| composite.exfil | composite | 2522 |
| composite.defense_evasion | composite | 160 |
| composite.execution | composite | 122 |
| composite.timeline | composite | 172 |
| composite.file_staging | composite | 578 |
| composite.persistence | composite | 2413 |
| composite.lateral_movement | composite | 472 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.correlation | composite | 1 |
| enrichment.iocs | enrichment | 67 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
