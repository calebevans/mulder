# Mulder Investigation Report

**Case:** nist-data-leakage
**Generated:** 2026-04-20T07:37:30.115810+00:00
**Evidence:** /evidence/nist-data-leakage

---

## Executive Summary

**Scope:** 8 evidence sources (43 disk, 2 other) | 167 tool calls | 30 minutes
**Results:** 10 findings (5 critical, 5 high) -- 10 confirmed, 0 inference | 1 hypothesis ruled out
**Timeline:** 2015-02-15 to 2015-03-25

**Key Threats:**
- Insider Threat: User "Iaman Informant" Exfiltrating Secret Project Data via USB
- Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com
- Premeditated Data Theft: Search History Shows Systematic Research on Leaking and Anti-Forensics
- Data Source: Secret Project Accessed from Network Share \\10.11.11.128\SECURED_DRIVE
- Resignation Letter Created After Anti-Forensic Cleanup

**Narrative:** The earliest activity was "Data Source: Secret Project Accessed from Network Share \\10.11.11.128\SECURED_DRIVE" (2015-02-15). The investigation subsequently uncovered "Resignation Letter Created After Anti-Forensic Cleanup"; "Premeditated Data Theft: Search History Shows Systematic Research on Leaking and Anti-Forensics". The most recent activity was "Eraser 6 Executed for Secure Deletion on 2015-03-25" (2015-03-25).

**Tools:** search (45), extract_file_by_inode (12), submit_finding (11), get_raw_output (9), check_extraction_status (9). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Insider Threat: User "Iaman Informant" Exfiltrating Secret Project Data via USB** 


- **Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com** 


- **Premeditated Data Theft: Search History Shows Systematic Research on Leaking and Anti-Forensics** (2015-03-25T14:31:53Z)


- **Data Source: Secret Project Accessed from Network Share \\10.11.11.128\SECURED_DRIVE** (2015-02-15T21:52:08Z -- 2015-03-22T14:52:21Z)


- **Resignation Letter Created After Anti-Forensic Cleanup** (2015-03-25T14:20:09Z -- 2015-03-25T15:28:33Z)





---

## Investigation Report

# NIST CFReDS 2015 Data Leakage Investigation Report

## Background

This investigation examines four forensic disk images from the NIST Computer Forensic Reference Data Sets (CFReDS) 2015 Data Leakage scenario: a Windows 7 PC workstation and three removable media devices (two USB drives and one CD-R). The investigation was initiated to determine whether classified project data was improperly accessed, copied, or exfiltrated from organizational systems, and to identify any anti-forensic measures employed to conceal such activity.

The evidence was processed using a comprehensive forensic toolkit including The Sleuth Kit (TSK) for filesystem analysis, bulk_extractor for data carving, and carved prefetch/LNK file analysis for execution and access timeline reconstruction. Registry and EVTX analysis was limited due to technical constraints with the multi-segment E01 disk image format.

## Incident Timeline

The investigation reveals a methodical, premeditated insider threat operation spanning approximately six weeks, from mid-February to late March 2015.

**Phase 1 — Research and Planning (Prior to February 15, 2015)**

User "Iaman Informant" (username: informant, work email: iaman.informant@nist.gov) conducted extensive web research into data theft methodologies and anti-forensic countermeasures. Search history recovered from the PC reveals hundreds of searches including "how to leak a secret," "information leakage cases," "intellectual property theft," "anti-forensic tools," "cd burning method," "security checkpoint cd-r," and "DLP DRM." The user systematically researched how forensic investigators analyze Windows machines, including searches for "windows event logs," "Forensic Email Investigation," "what is windows system artifacts," and "external device and forensics." This research demonstrates clear premeditation and sophisticated awareness of forensic detection capabilities.

**Phase 2 — Data Collection and Exfiltration (February 15 – March 22, 2015)**

On February 15, 2015, at approximately 21:52 UTC, the user copied classified "Secret Project Data" from an internal network file share (\\\\10.11.11.128\\SECURED_DRIVE, mapped as drive V:) to a USB drive labeled "Authorized USB" (rm1, exFAT filesystem). LNK file analysis confirms the following files were copied to E:\\RM#1\\Secret Project Data\\:
- Design documents: [secret_project]_design_concept.ppt, [secret_project]_detailed_design.pptx, [secret_project]_revised_points.ppt
- Proposal documents: [secret_project]_detailed_proposal.docx, [secret_project]_proposal.docx (originally created December 19, 2014)

The user also installed Google Drive Sync (downloaded from the internet) and configured it with a personal Gmail account (iaman.informant.personal@gmail.com) distinct from their work email. The Google Drive sync folder was established at Users\\informant\\Google Drive\\, and prefetch evidence confirms the GOOGLEDRIVESYNC.EXE executable was run. Additionally, the user downloaded icloudsetup.exe, suggesting Apple iCloud was also considered as an exfiltration channel.

On March 22, 2015, at 14:52:21 UTC, the user again accessed the network share to retrieve additional files, including pricing decision documents and files from a "final" directory.

A second USB drive (rm2, FAT32) contains deleted files organized in project management folder categories (design, pricing, progress, proposal, technical) that mirror the secret project structure, indicating it was previously used to transport data. Notably, six "diary" text files were found in the deleted technical folder. A CD-R (rm3) was also burned using Windows' built-in CD burning feature, containing Word documents with embedded images processed in Adobe Photoshop CS.

**Phase 3 — Anti-Forensic Cleanup and Resignation (March 25, 2015)**

On March 25, 2015, the user conducted a systematic cleanup operation during a single session:

- 14:41:03 UTC — Outlook opened (single execution)
- 14:50:14 UTC — Eraser 6.2.0.2962 installer downloaded and executed
- 14:58:35 UTC — CCleaner64.exe accessed for system cleanup
- 15:13:30 UTC — Eraser.exe executed (2 runs) for secure file deletion
- 15:22:07 UTC — Internet Explorer used (possibly checking for remaining traces)
- 15:28:33 UTC — Resignation_Letter_(Iaman_Informant).xps created

Both the Eraser and CCleaner installers were subsequently deleted from Users\\informant\\Desktop\\Download\\, though their Zone.Identifier alternate data streams confirm they were downloaded from the internet. The Google Drive sync databases (snapshot.db, sync_config.db) were also deleted to destroy evidence of what files were synchronized to the cloud.

## Key Findings

**1. Systematic Data Exfiltration via Multiple Channels (CRITICAL)**
The insider exfiltrated classified project data through at least four channels: USB drive (rm1 "Authorized USB"), Google Drive (personal Gmail account), CD-R (rm3), and a second USB drive (rm2, files subsequently deleted). This multi-channel approach demonstrates operational security awareness and intent to ensure data availability outside the organization.

**2. Premeditated Intent Demonstrated by Search History (CRITICAL)**
Web search history containing over 900 searches across data theft planning, exfiltration methods, anti-forensic tools, and counter-investigation research constitutes compelling evidence of deliberate, premeditated intent. The user specifically researched how to bypass physical security with a CD-R and how to evade forensic detection.

**3. Network Share as Data Source (CRITICAL)**
The classified data originated from a secured network file share at \\\\10.11.11.128\\SECURED_DRIVE, which was mapped as drive V: on the informant's PC. LNK file timestamps provide precise access times for this resource.

**4. Anti-Forensic Countermeasures Deployed (HIGH)**
The user downloaded and executed Eraser 6 (secure deletion), CCleaner (system cleanup), and manually deleted installer files, Google Drive databases, and files from USB rm2. The deliberate destruction of evidence occurred during the same session in which the resignation letter was created.

**5. Personal Gmail Used for Cloud Exfiltration (CRITICAL)**
The Google Drive installation was configured with iaman.informant.personal@gmail.com, a personal Gmail account separate from the work account, ensuring exfiltrated data would remain accessible after departure from the organization.

## Impact Assessment

The data impact is significant. Classified project documents including design specifications (PPT/PPTX), detailed proposals (DOCX), and pricing decisions (XLSX) were exfiltrated. The documents appear to represent a complete project portfolio with strategic, technical, and financial information. The use of multiple exfiltration channels (USB, cloud, CD-R) increases the likelihood that the data has been disseminated beyond the insider's immediate control.

The anti-forensic cleanup was partially effective — Google Drive sync logs and databases were destroyed, preventing definitive determination of all files synchronized to the cloud. However, the cleanup was incomplete: prefetch files, LNK file artifacts, bulk_extractor carved data, and web search history all survived, providing a comprehensive reconstruction of the insider's activities.

## Recommendations

1. **Immediate Actions**: Revoke all access credentials for user iaman.informant@nist.gov. Disable the personal Gmail account's access to any organizational OAuth integrations. Preserve the Google Drive account content via legal process.

2. **Network Investigation**: Audit all access to \\\\10.11.11.128\\SECURED_DRIVE to determine the full scope of data accessed by this user and whether any other users may have been involved.

3. **Device Recovery**: Forensically examine all personal devices associated with the suspect. Subpoena Google for the contents of iaman.informant.personal@gmail.com Google Drive storage.

4. **Policy Improvements**: Implement DLP controls to monitor and restrict bulk file transfers to removable media and cloud storage services. Enforce USB device whitelisting. Monitor for anti-forensic tool installation via endpoint detection.

5. **Legal Considerations**: The evidence supports referral for criminal investigation. The premeditation demonstrated by web searches, the multi-channel exfiltration approach, the anti-forensic cleanup, and the resignation timing collectively establish intent.

## Conclusion

This investigation conclusively establishes that user "Iaman Informant" (iaman.informant@nist.gov) conducted a premeditated insider theft of classified project data from the organization's secured network share. The user methodically researched data theft and anti-forensic techniques, exfiltrated data through multiple channels (USB drives, Google Drive with a personal Gmail account, and a CD-R), deployed anti-forensic tools (Eraser 6 and CCleaner) to destroy evidence, and created a resignation letter as their final act. Despite the cleanup efforts, sufficient forensic artifacts survived to reconstruct the complete timeline and scope of the data theft. The investigation found no evidence of external attackers or a second independent incident — all activity is attributable to the single insider threat actor.


---

## Overview

| | |
|---|---|
| Findings | **10** (10 confirmed, 0 inference) |
| Severity | 5 critical, 5 high, 0 medium, 0 low, 0 info |
| Sources | 8 evidence sources across 167 tool calls |
| Ruled Out | 1 hypotheses tested and rejected |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| cfreds_2015_data_leakage_pc.E01 | `e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9` | 2.0 GB |
| cfreds_2015_data_leakage_rm1.E01 | `a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121` | 74.6 MB |
| cfreds_2015_data_leakage_rm2.E01 | `25215f9bcb51ceee9147886ed3f5c13ef148de634fc5114491e0f8dad8b15696` | 243.2 MB |
| cfreds_2015_data_leakage_rm3.E01 | `336e1307721ef5f63679379961d1716b74f986e69df8c40117d9cea7858d512b` | 90.2 MB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2015-02-15T21:52:08Z | Data Source: Secret Project Accessed from Network Share \\10.11.11.128\SECURED_DRIVE | CRITICAL | bulk.winlnk |
| 2015-03-25T14:20:09Z | Resignation Letter Created After Anti-Forensic Cleanup | CRITICAL | bulk.winlnk, bulk.winprefetch |
| 2015-03-25T14:31:53Z | Premeditated Data Theft: Search History Shows Systematic Research on Leaking and Anti-Forensics | CRITICAL | bulk.url_searches, bulk.url |
| 2015-03-25T14:50:14Z | Eraser 6 Executed for Secure Deletion on 2015-03-25 | HIGH | bulk.winprefetch |



---

## Findings


### 1. [CRITICAL] Insider Threat: User "Iaman Informant" Exfiltrating Secret Project Data via USB

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_8e82fae8, tc_a3962ede |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


User account "informant" (full name "Iaman Informant" per resignation letter filename) on the PC has copied classified "Secret Project Data" to a USB drive labeled "Authorized USB" (rm1, exFAT). The USB contains:
- Secret Project Data/design/[secret_project]_design_concept.ppt
- Secret Project Data/design/[secret_project]_detailed_design.pptx
- Secret Project Data/design/[secret_project]_revised_points.ppt
- Secret Project Data/proposal/[secret_project]_detailed_proposal.docx
- Secret Project Data/proposal/[secret_project]_proposal.docx
- A duplicate copy exists under "RM#1/" directory on the same USB
- Temp file ~$ecret_project]_proposal.docx indicates active editing

The PC shows LNK files confirming the user accessed these files:
- Users/informant/AppData/Roaming/Microsoft/Office/Recent/[secret_project]_design_concept.LNK
- Users/informant/AppData/Roaming/Microsoft/Windows/Recent/[secret_project]_proposal.lnk
- Users/informant/AppData/Roaming/Microsoft/Windows/Recent/(secret_project)_pricing_decision.xlsx.lnk



### 2. [CRITICAL] Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | bulk.email |
| **Evidence Refs** | tc_1a840139, tc_5ba33c9e |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |


The Google Drive sync configuration on the PC reveals the insider used a personal Gmail account for data exfiltration:

From bulk_extractor email carving (PC image, offset 7024636280):
```
Config:
Email: iaman.informant.personal@gmail.com
Sync root: \\?
```

This confirms the Google Drive installation was configured with the suspect's personal Gmail, not their work email (iaman.informant@nist.gov). The sync folder at Users/informant/Google Drive/ contained files (happy_holiday.jpg - now deleted). The sync databases (snapshot.db, sync_config.db) were deliberately deleted to destroy evidence of which files were synced to the cloud.

Key email addresses identified:
- Work: iaman.informant@nist.gov (Outlook configured with this)
- Personal Gmail for exfiltration: iaman.informant.personal@gmail.com
- Contact in documents: wayne.longman@att.net (found on rm2 and rm3)
- Government contact: Eric_P._Lauer@omb.eop.gov



### 3. [CRITICAL] Premeditated Data Theft: Search History Shows Systematic Research on Leaking and Anti-Forensics

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:31:53Z |
| **Sources** | bulk.url_searches, bulk.url |
| **Evidence Refs** | tc_a09de574, tc_f0a90efb |
| **ATT&CK** | [T1119](https://attack.mitre.org/techniques/T1119/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


User "informant" conducted extensive web searches demonstrating premeditation and intent to steal data and evade detection. Key searches by frequency:

**Data Theft Planning:**
- "file sharing and tethering" (n=491)
- "information leakage cases" (n=47)
- "how to leak a secret" (n=6)
- "intellectual property theft" (n=6)
- "leaking confidential information" (n=2)
- "data leakage methods" (n=1)

**Exfiltration Methods Researched:**
- "cloud storage" (n=6)
- "google drive" (n=10)
- "apple icloud" (n=1)
- "cd burning method" (n=64)
- "cd burning method in windows" (n=53)
- "security checkpoint cd-r" (n=1) — researching how to get CD through physical security

**Anti-Forensics Research:**
- "anti-forensic tools" (n=85)
- "anti-forensics" (n=1+)
- "ccleaner" (n=65)
- "eraser" (n=51)
- "how to delete data" (n=5)
- "system cleaner" (n=5+)

**Counter-Investigation Research:**
- "e-mail investigation" (n=88)
- "Forensic Email Investigation" (n=78)
- "what is windows system artifacts" (n=79)
- "external device and forensics" (n=65)
- "investigation on windows machine" (n=64)
- "windows event logs" (n=61)
- "digital forensics" (n=1+)
- "DLP DRM" (n=90) — researching Data Loss Prevention

**Data Recovery Awareness:**
- "data recovery tools" (n=4+)
- "how to recover data" (n=2+)

The Google search parameter contains the Google Search EI timestamp: ei=3VUQVYH3FMO1sQTf1YGwBw — this encodes to approximately March 2015.



### 4. [CRITICAL] Data Source: Secret Project Accessed from Network Share \\10.11.11.128\SECURED_DRIVE

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T21:52:08Z -- 2015-03-22T14:52:21Z |
| **Sources** | bulk.winlnk |
| **Evidence Refs** | tc_58800ff3, tc_f0a90efb |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


LNK file analysis reveals the secret project data originated from a network file share:
- Network path: \\10.11.11.128\SECURED_DRIVE
- Mapped as drive: V:
- Files accessed at 2015-03-22T14:52:21Z:
  - Secret Project Data\pricing decision\(secret_project)_pricing_decision.xlsx (modified 2015-01-29T20:3x)
  - Secret Project Data\final directory

USB "Authorized USB" (rm1) LNK timestamps show data copy to drive E: occurred on 2015-02-15:
- E:\RM#1\Secret Project Data\design\ accessed 2015-02-15T21:52:08Z
- E:\RM#1\Secret Project Data\proposal\ accessed 2015-02-15T21:52:12Z
- E:\RM#1\Secret Project Data\proposal\[secret_project]_proposal.docx accessed 2015-02-15T21:52:20Z (file originally modified 2014-12-19T19:53:46Z)

The informant accessed the secure network drive and copied classified project documents including design specifications, proposals, and pricing decisions to a personal USB drive.



### 5. [CRITICAL] Resignation Letter Created After Anti-Forensic Cleanup

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:20:09Z -- 2015-03-25T15:28:33Z |
| **Sources** | bulk.winlnk, bulk.winprefetch |
| **Evidence Refs** | tc_e42120ea, tc_e765ef43 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070](https://attack.mitre.org/techniques/T1070/) |


The resignation letter was the final artifact created during the insider's last session:

LNK file evidence:
- Resignation_Letter_(Iaman_Informant).xps created at 2015-03-25T15:28:33Z
- CCleaner64.exe LNK accessed at 2015-03-25T14:58:35Z (CCleaner installed 2015-03-13T11:10:26Z)

Complete session timeline on March 25, 2015:
1. 14:20:09 - Task engine started
2. 14:31:53 - Console host
3. 14:41:03 - Outlook opened (1 run)
4. 14:42:47 - Windows Media Player
5. 14:50:14 - Eraser 6 INSTALLER executed
6. 14:50:17-14:54:29 - Installer components (.NET, ASP.NET)
7. 14:57:18 - VSS service
8. 14:58:35 - CCleaner64.exe accessed (cleanup performed)
9. 15:13:30 - Eraser.exe executed (secure deletion, 2 runs)
10. 15:22:07 - Internet Explorer (14 total runs)
11. 15:28:33 - Resignation_Letter_(Iaman_Informant).xps CREATED

The user systematically: (1) installed cleanup tools, (2) ran secure deletion, (3) ran CCleaner, (4) browsed for any remaining traces, then (5) created the resignation letter as their final act.



### 6. [HIGH] Anti-Forensic Tool Installation: Eraser 6 and CCleaner Downloaded and Executed

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_8e82fae8, tc_8e73d148 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/) |


User "informant" downloaded and installed two anti-forensic/cleanup tools:

1. Eraser 6.2.0.2962 - Secure deletion tool
   - Downloaded to: Users/informant/Desktop/Download/Eraser 6.2.0.2962.exe (DELETED, Zone.Identifier present - downloaded from internet)
   - Installed to: Program Files/Eraser/
   - Prefetch files confirm execution: ERASER 6.2.0.2962.EXE-BE552234.pf and ERASER.EXE-CE61944A.pf
   - Task list at: Users/informant/AppData/Local/Eraser 6/Task List.ersy
   - Shortcuts created on Public Desktop and Start Menu

2. CCleaner v5.04 - System cleanup tool
   - Downloaded to: Users/informant/Desktop/Download/ccsetup504.exe (DELETED, Zone.Identifier present)
   - Prefetch confirms execution: CCLEANER64.EXE-779BD542.pf and CCSETUP504.EXE-6BA2F6A1.pf
   - Shortcut on Public Desktop (DELETED)

Both installer files were subsequently deleted, likely to hide evidence of the tools. The Eraser tool can securely delete files making recovery impossible, and CCleaner removes browser history, temp files, and other forensic artifacts.



### 7. [HIGH] Cloud Storage Exfiltration Channel: Google Drive Sync Installed and Active

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_8e82fae8, tc_2f0a4dbc |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1048](https://attack.mitre.org/techniques/T1048/) |


User "informant" installed Google Drive Sync as an additional data exfiltration channel:
- Downloaded: Users/informant/Downloads/googledrivesync.exe (with Zone.Identifier - internet download)
- Installed: Program Files (x86)/Google/Drive/googledrivesync.exe
- Prefetch confirms execution: GOOGLEDRIVESYNC.EXE-841A0D94.pf
- Local sync folder: Users/informant/Google Drive/ (contained happy_holiday.jpg - DELETED)
- Drive databases: Users/informant/AppData/Local/Google/Drive/user_default/ (snapshot.db, sync_config.db - DELETED)
- Sync log exists: Users/informant/AppData/Local/Google/Drive/user_default/sync_log.log
- Desktop shortcut to Google Drive (DELETED)
- IE DOM Store contains drive.google[1].xml - accessed Google Drive via browser
- Also downloaded: icloudsetup.exe - suggesting iCloud was considered as another channel

The deletion of the Google Drive databases (snapshot.db, sync_config.db) indicates deliberate cleanup of sync history.



### 8. [HIGH] Deleted Data on USB rm2 (FAT32): Previously Stored Secret Project Folders

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_45ce2bb6 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


The FAT32 USB drive (rm2) contains deleted files organized in the same folder structure as the secret project data, indicating it was previously used to store/transport sensitive data before deletion:

Deleted folders and files found in $OrphanFiles:
- design/winter_storm.amr, design/winter_whether_advisory.zip
- PRICIN~1 (pricing)/my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi
- progress/my_friends.svg, my_smartphone.png, new_year_calendar.one
- proposal/a_gift_from_you.gif, landscape.png
- TECHNI~1 (technical)/diary_#1d.txt through diary_#3p.txt (6 diary files)
- Many deleted image files: amalfi.bmp, barn.gif, etc.

The folder names (design, pricing, progress, proposal, technical) mirror project management categories. The "diary" files in the TECHNI~1 folder may contain sensitive technical notes. The volume label "IAMAM $_@" appears corrupted. Files were deleted but recoverable from FAT32 orphan entries.



### 9. [HIGH] Eraser 6 Executed for Secure Deletion on 2015-03-25

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:50:14Z -- 2015-03-25T15:13:30Z |
| **Sources** | bulk.winprefetch |
| **Evidence Refs** | tc_7a772ef2, tc_e765ef43 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/) |


Prefetch analysis confirms Eraser 6 was installed and used for secure file deletion:
- ERASER 6.2.0.2962.EXE installer: Last run 2015-03-25T14:50:14Z (1 run)
- ERASER.EXE application: Last run 2015-03-25T15:13:30Z (2 runs)

Timeline of March 25, 2015 activity:
- 14:41:03 - Outlook opened (1 run)
- 14:42:47 - Windows Media Player (1 run)
- 14:50:14 - Eraser 6 installer executed
- 14:50:17 - Setup.exe (related to Eraser install)
- 15:13:30 - Eraser.exe executed (secure deletion performed)
- 15:22:07 - Internet Explorer (browsing continued)

The Eraser installation and execution occurred within the same session, indicating deliberate and immediate use of the tool to destroy evidence. The task list at Users/informant/AppData/Local/Eraser 6/Task List.ersy may reveal what was targeted for deletion.



### 10. [HIGH] CD-R (rm3) Contains Image Files - Used as Data Exfiltration Medium

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Sources** | strings.output, bulk.exif, tsk.filelist |
| **Evidence Refs** | tc_5da8e1fc, tc_5bf124dc, tc_8b5d41ec, tc_3f2e9f88 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1027](https://attack.mitre.org/techniques/T1027/) |


The CD-R disk image (rm3) was detected with high entropy (7.65) by fls, initially suggesting encryption. String analysis reveals the CD-R contains JPEG image files:

- EXIF data shows Eastman Kodak Company KODAK DIGITAL SCIENCE DC260 camera
- Image timestamps: 2003:09:24 15:33:42 and 2003:12:10 17:27:44
- LEAD Technologies Inc. V1.01 image library markers
- Adobe Photoshop CS processed images

Bulk_extractor carved from rm3:
- 60 domain entries, 3 email entries, 6 EXIF entries, 11 RFC822 entries (Library of Congress catalog data)
- 75 URL entries including digitalcorpora.org, whitehouse.gov, hdl.loc.gov references

The user researched "cd burning method in windows" (n=53) and "security checkpoint cd-r" (n=1), showing deliberate planning to use a CD-R to bypass physical security. The Windows Burn staging directory at Users/informant/AppData/Local/Microsoft/Windows/Burn/Burn/ contains deleted entries confirming CD burning activity.

The RFC822 data contains Library of Congress catalog records, suggesting the CD-R may contain both innocuous reference materials and potentially hidden/steganographic data to pass through security checkpoints.




---

## Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No Evidence of External Attacker or Second Independent Incident** -- Counter-hypothesis analysis was performed to look for evidence of activity outside the primary insider threat narrative:

1. User account audit: Three user accounts exist (admin11, informant,...



---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| Internal IP | `10.11.11.128` | Data Source: Secret Project Accessed from Network Share \\10.11.11.128\SECURED_D |


### File IOCs

| Type | Value | Context |
|------|-------|---------|
| Path | `/Windows/Recent/[secret_project]_proposal.lnk` | Insider Threat: User "Iaman Informant" Exfiltrating Secret Project Data via USB |
| Path | `/Windows/Recent/(secret_project)_pricing_decision.xlsx.lnk` | Insider Threat: User "Iaman Informant" Exfiltrating Secret Project Data via USB |
| Path | `/Windows/Burn/Burn/` | CD-R (rm3) Contains Image Files - Used as Data Exfiltration Medium |



### Email IOCs

| Type | Value | Context |
|------|-------|---------|
| Email | `iaman.informant.personal@gmail.com` | Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com |
| Email | `iaman.informant@nist.gov` | Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com |
| Email | `wayne.longman@att.net` | Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com |
| Email | `eric_p._lauer@omb.eop.gov` | Google Drive Exfiltration via Personal Gmail: iaman.informant.personal@gmail.com |




---

## MITRE ATT&CK Coverage

12 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) &#8594; Persistence (1) &#8594; Privilege Escalation (1) &#8594; Defense Evasion (4) &#8594; Collection (4) &#8594; Exfiltration (3) &#8594; Impact (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Google Drive Exfiltration via Personal Gmail:... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Google Drive Exfiltration via Personal Gmail:... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Google Drive Exfiltration via Personal Gmail:... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | CD-R (rm3) Contains Image Files - Used as Data... |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | Resignation Letter Created After Anti-Forensic Cleanup |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Anti-Forensic Tool Installation: Eraser 6 and...; Deleted Data on USB rm2 (FAT32): Previously...; Eraser 6 Executed for Secure Deletion on 2015-03-25; Resignation Letter Created After Anti-Forensic Cleanup |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Google Drive Exfiltration via Personal Gmail:... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Data Source: Secret Project Accessed from... |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Data Source: Secret Project Accessed from... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Insider Threat: User "Iaman Informant"...; Deleted Data on USB rm2 (FAT32): Previously... |
| [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Premeditated Data Theft: Search History Shows... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Cloud Storage Exfiltration Channel: Google... |
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Insider Threat: User "Iaman Informant"...; Premeditated Data Theft: Search History Shows...; Data Source: Secret Project Accessed from...; CD-R (rm3) Contains Image Files - Used as Data... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Cloud Storage Exfiltration Channel: Google...; Google Drive Exfiltration via Personal Gmail:...; Premeditated Data Theft: Search History Shows... |


### Impact

| Technique | Name | Findings |
|-----------|------|----------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Anti-Forensic Tool Installation: Eraser 6 and...; Eraser 6 Executed for Secure Deletion on 2015-03-25 |





---

## Audit Trail

| Metric | Value |
|--------|-------|
| Total tool calls | 167 |
| Findings submitted | 10 |
| Confirmed | 10 |
| Inferences | 0 |
| Audit log | /root/.mulder/cases/nist-data-leakage.audit.jsonl |


<details>
<summary>Evidence Sources (45)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.fsstat | sleuthkit | 0 |
| tsk.fsstat | sleuthkit | 0 |
| tsk.fsstat | sleuthkit | 0 |
| tsk.fsstat | sleuthkit | 0 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 9 |
| tsk.partitions | sleuthkit | 10 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 16 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.domain | bulk_extractor | 189 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 27 |
| tsk.filelist | sleuthkit | 104709 |
| bulk.alerts | bulk_extractor | 11 |
| bulk.domain | bulk_extractor | 366644 |
| bulk.email | bulk_extractor | 6532 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 793 |
| bulk.ip | bulk_extractor | 29 |
| bulk.packets | bulk_extractor | 166 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.tcp | bulk_extractor | 15 |
| bulk.url | bulk_extractor | 421750 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| bulk.winlnk | bulk_extractor | 466 |
| bulk.winpe | bulk_extractor | 28636 |
| bulk.winpe_carved | bulk_extractor | 28630 |
| bulk.winprefetch | bulk_extractor | 155 |
| binwalk.scan | binwalk | 0 |
| strings.output | strings | 10090 |


</details>


---

*Report generated by [Mulder](https://github.com/caevans/mulder) -- AI-driven forensic investigation via MCP*
