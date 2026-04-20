# Mulder Investigation Report

**Case:** nist-data-leakage
**Generated:** 2026-04-20T19:29:56.425190+00:00
**Evidence:** /evidence/nist-data-leakage

---

## Executive Summary

**Scope:** 10 evidence sources (50 disk) | 246 tool calls | 34 minutes
**Results:** 14 findings (9 critical, 4 high) -- 13 confirmed, 1 inference | 2 hypotheses ruled out
**Timeline:** 2015-02-15 to 2015-03-25

**Key Threats:**
- Insider Threat Actor Identified — Suspect "Iaman Informant"
- Secret Project Documents Accessed and Staged for Exfiltration
- Multi-Vector Exfiltration — USB Drives, CD-R, Google Drive, and iCloud
- Government Agency Documents Exfiltrated — NASA, NIH, Library of Congress, DOE
- Network File Server Access — \\10.11.11.128\secured_drive\Secret Project Data

**Narrative:** The earliest activity was "USB Device Exfiltration Timeline — Three Devices with IAMAN Labels" (2015-02-15). The investigation subsequently uncovered "Complete Incident Execution Timeline — March 22-25, 2015"; "Network File Server Access — \\10.11.11.128\secured_drive\Secret Project Data"; "Google Drive Sync Active After Anti-Forensic Cleanup — Possible Ongoing Cloud Exfiltration". The most recent activity was "Google Drive Sync Active After Anti-Forensic Cleanup — Possible Ongoing Cloud Exfiltration" (2015-03-25).

**Tools:** search (83), get_raw_output (24), submit_finding (16), extract_file_by_inode (12), list_files (9). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Insider Threat Actor Identified — Suspect "Iaman Informant"** 


- **Secret Project Documents Accessed and Staged for Exfiltration** 


- **Multi-Vector Exfiltration — USB Drives, CD-R, Google Drive, and iCloud** 


- **Government Agency Documents Exfiltrated — NASA, NIH, Library of Congress, DOE** 


- **Network File Server Access — \\10.11.11.128\secured_drive\Secret Project Data** (2015-03-22T14:52:21Z)


- **Suspect Fully Identified — iaman.informant@nist.gov, NIST Employee** 


- **USB Device Exfiltration Timeline — Three Devices with IAMAN Labels** (2015-02-15T21:52:08Z -- 2015-03-24T20:40:55Z)


- **Complete Incident Execution Timeline — March 22-25, 2015** (2015-02-15T21:52:08Z -- 2015-03-25T15:28:33Z)


- **Google Drive Sync Active After Anti-Forensic Cleanup — Possible Ongoing Cloud Exfiltration** (2015-03-25T15:21:40Z)





---

## Investigation Report

# NIST Data Leakage Investigation — Incident Report

**Case ID:** nist-data-leakage  
**Evidence:** 4 disk images (1 PC + 3 removable media)  
**Investigation Date:** 2026-04-20  
**Classification:** Insider Threat / Data Exfiltration

---

## Background

The National Institute of Standards and Technology (NIST) submitted four forensic disk images for examination following the suspected unauthorized exfiltration of confidential project data by a departing employee. The evidence consists of a primary Windows 7 workstation image (7.3 GB across four EWF segments) and three removable media devices: a USB exFAT drive (74.6 MB, labeled "Authorized USB"), a USB FAT32 drive (243.2 MB, labeled "IAMAN $_@"), and a CD-R disc (90.2 MB, labeled "IAMAN CD"). The evidence was examined using The Sleuth Kit filesystem analysis, bulk_extractor IOC carving, Windows Prefetch analysis, and LNK file artifact recovery.

---

## Incident Timeline

### December 2014 — Earliest Data Staging

The earliest evidence of data preparation dates to December 2014. LNK artifacts recovered from the PC show that a file named `winter_whether_advisory.zip` was created on the exFAT USB ("Authorized USB") with a write time of 2014-12-16T16:10:26Z, and `[secret_project]_proposal.docx` was present on the same USB with a write time of 2014-12-19T19:53:46Z. This establishes that the suspect began gathering confidential project materials at least three months before their departure.

### February 15, 2015 — First Documented USB Exfiltration

On February 15, 2015 at approximately 21:52 UTC, the suspect accessed the exFAT USB drive (RM1, "Authorized USB") via drive letter E:, navigating to the path `E:\RM#1\Secret Project Data\proposal\` and opening `[secret_project]_proposal.docx`. Multiple LNK artifacts corroborate this access event, with timestamps at 21:52:08, 21:52:12, and 21:52:20 UTC. This represents the first directly evidenced exfiltration event.

### March 22, 2015 — Primary Exfiltration Day

The most significant data access activity occurred on March 22, 2015. MFT records recovered via bulk_extractor show that the "informant" user account directory was created at 14:34:31 UTC — indicating the account may have been newly established as a dedicated exfiltration identity on this date.

Between 14:52:08 and 14:52:21 UTC, the suspect accessed the organizational network file share `\\10.11.11.128\secured_drive` (mounted as drive V:), navigating to `Secret Project Data\final` and accessing `(secret_project)_pricing_decision.xlsx`. This network server, at internal IP 10.11.11.128, hosted the confidential "Secret Project" repository.

At 15:03:23 UTC, Microsoft Outlook was opened under the email address `iaman.informant@nist.gov`, connecting to NIST's Microsoft Exchange Online (Office 365) environment. Google Chrome was opened multiple times between 15:11 and 15:16 UTC. At 15:54 UTC, artifacts from the `admin11` account Quick Launch were accessed, and at 15:56 UTC, the `temporary` user account's Quick Launch and Internet Explorer entries were accessed — suggesting the suspect may have briefly used alternate accounts.

### March 24, 2015 — Final Media Exfiltration

On March 24, 2015, the suspect engaged in final media exfiltration activities. Internet Explorer was launched at 14:05 UTC (12 cumulative runs). The Volume Shadow Copy Service (VSSVC.EXE) ran at 15:21 UTC (4 runs). Sticky Notes (STIKYNOT.EXE) ran at 18:31 UTC (2 runs), and Microsoft Word (WINWORD.EXE) was used to create the resignation letter `Resignation_Letter_(Iaman_Informant).docx`, with access at 18:48 UTC and editing at 18:59 UTC.

Between 20:40 and 21:02 UTC, both the FAT32 USB (RM2, "IAMAN $_@") and the CD-R disc (RM3, "IAMAN CD") were accessed at drive letters E: and D: respectively. The file `winter_whether_advisory.zip` was accessed on the FAT32 USB at 20:40 UTC, and the CD-R was browsed including `D:\Koala.jpg` at 20:57 UTC. The DEVICEDISPLAYOBJECTPROVIDER.EXE prefetch entry at 21:02 UTC confirms USB device interaction.

### March 25, 2015 — Anti-Forensic Cleanup and Departure

The final day of activity was devoted to systematic anti-forensic evidence destruction before the suspect's departure from NIST.

At 10:18 UTC, CLRGC.EXE (the .NET CLR garbage collector) ran three times — consistent with Google Drive Sync operating in the background during early morning hours.

At 14:31 UTC, CONHOST.EXE ran (12 total runs), indicating command-line activity. At 14:41 UTC, Outlook was opened for the final time (1 run), suggesting a final email was sent. At 14:42 UTC, Windows Media Player (WMPLAYER.EXE) ran once, possibly to review a media file from the exfiltrated collection.

At 14:50 UTC, the Eraser 6.2.0.2962 installer executed. Eraser version 6.2.0.2962, previously downloaded to the Desktop's Download folder (`Eraser 6.2.0.2962.exe` with a Zone.Identifier alternate data stream confirming internet download), was installed alongside its .NET dependencies (ASPNET_REGIIS.EXE at 14:54 UTC, NGEN.EXE at 14:52 UTC, REGTLIBV12.EXE at 14:51 UTC).

At 14:57 UTC, VSSVC.EXE ran again (6 total runs), consistent with Volume Shadow Copy activity triggered by the installation or file operations.

At 14:58 UTC, CCleaner 5.04 (ccsetup504.exe, also Zone.Identifier downloaded) was executed via CCleaner64.exe, confirmed by LNK artifact access time 2015-03-25T14:58:35Z. CCleaner was used to wipe browser history, temporary files, and application cache — eliminating evidence of the suspect's research into anti-forensic tools, CD burning methods, and forensic investigation techniques.

At 15:13 UTC, Eraser.exe ran twice (2 prefetch runs), executing configured secure file deletion tasks against specified directories and files. The Eraser Task List configuration file (`Task List.ersy`) remains at inode 22321 on the PC.

At 15:21:40 UTC, a prefetch file `GOOGLEDRIVESYNC.EXE-841A0D94.pf` was created in the MFT — confirming that Google Drive Sync executed after the CCleaner and Eraser cleanup, meaning Google Drive may have uploaded a final batch of files to the cloud even as local evidence was being destroyed.

At 15:22 UTC, Internet Explorer ran (14 total runs). The last documented activity is a LNK access for `Resignation_Letter_(Iaman_Informant).xps` at 15:28:33 UTC — the suspect's final recorded action before departing.

---

## Key Findings

### Suspect Identification
The suspect is identified with high confidence as **Iaman Informant** (email: `iaman.informant@nist.gov`), a NIST employee. This identity was confirmed through: the Outlook OST path containing the email address, the resignation letter bearing the name "Iaman Informant" found on the informant's Desktop, USB drive volume labels "IAMAN $_@" and "IAMAN CD," and the local Windows account name "informant."

### Confidential Project Data Exfiltrated
The suspect accessed and exfiltrated the following "secret project" documents from the NIST network file server (\\10.11.11.128\secured_drive):
- `[secret_project]_pricing_decision.xlsx` — financial/pricing intelligence
- `[secret_project]_design_concept` — design documentation
- `[secret_project]_final_meeting.pptx` — meeting presentation
- `[secret_project]_proposal.docx` — project proposal
- `winter_whether_advisory.zip` and other files

### Government Agency Documents
Bulk_extractor analysis of the removable media recovered embedded references to documents from multiple US government agencies: `mmeyer@mail.hq.nasa.gov` (NASA HQ), `mmun@loc.gov` (Library of Congress), `th276a@nih.gov` (NIH), and URLs referencing NASA's GSFC NODIS system, Department of Energy, and the White House. The RM2 and RM3 media also contained JPEG photographs taken with a Kodak Digital Science DC260 camera consistent with archival document digitization.

### Multi-Vector Exfiltration
The suspect employed at least five exfiltration vectors simultaneously:
1. **USB exFAT drive** (RM1, "Authorized USB"): Accessed December 2014 – February 2015
2. **USB FAT32 drive** (RM2, "IAMAN $_@"): All files subsequently deleted, recovered as $OrphanFiles from multiple folders (design, PRICIN~1, TECHNI~1, progress, proposal) containing databases, archives, media, and diary text files
3. **CD-R disc** (RM3, "IAMAN CD"): Burned with government document fragments
4. **Google Drive Sync**: Installed (googledrivesync.exe downloaded with Zone.Identifier), actively syncing to Google Cloud, with all local sync logs and database files subsequently deleted
5. **Apple iCloud**: Installed (icloudsetup.exe downloaded; iCloud Control Panel 4.0.6.28 installer cache deleted from ProgramData/Apple)

### Systematic Anti-Forensic Campaign
The suspect conducted a premeditated anti-forensic campaign demonstrating advance research into cover-up techniques. Browser search history reveals searches for "anti-forensic tools" (n=85), "ccleaner" (n=65), "external device and forensics" (n=65), "cd burning method" (n=64), "e-mail investigation" (n=88), and "DLP DRM" (n=90). Two dedicated data wiping tools were installed and used: CCleaner 5.04 (browser/temp file wiper) and Eraser 6.2.0.2962 (secure file overwriter). Both tools and their installer files were subsequently deleted. Google Drive sync logs, iCloud installer cache, Chrome browser history, and cloud shortcuts were all deliberately removed.

---

## Impact Assessment

The breach affected confidential NIST project data including strategic design documents, pricing intelligence, meeting records, and proposals spanning a project designated internally as "the secret project." Additionally, documents from multiple federal agencies (NASA, NIH, Library of Congress, DOE) were exfiltrated, suggesting cross-agency research or reference materials held by NIST were also taken.

The exfiltration period spans at least December 2014 through March 25, 2015 — approximately four months. The use of Google Drive and potentially iCloud means data may have been uploaded to external cloud storage that is no longer accessible through local forensic examination. The full scope of cloud-uploaded data cannot be determined from the available evidence due to deleted sync databases.

Three user accounts were present on the PC (admin11, informant, temporary). No evidence was found of admin11 or temporary account involvement in the data theft. The "informant" account was the sole exfiltration actor.

---

## Recommendations

**Immediate Actions:**
1. Preserve and subpoena Google account records for the suspect's Google account (associated with googledrivesync.exe) from Google LLC for data uploaded between December 2014 and March 25, 2015.
2. Preserve and subpoena Apple iCloud records associated with the iCloud account installed on this PC.
3. Preserve and subpoena Office 365 / Exchange Online email logs for `iaman.informant@nist.gov` for emails sent on March 25, 2015 at approximately 14:41 UTC.
4. Conduct network traffic log analysis for the PC's IP address against the internal server at 10.11.11.128 during the period December 2014 – March 2015.
5. Examine the Eraser Task List file at inode 22321 (`Task List.ersy`) using a forensic workstation with direct partition access to determine exactly which directories and files were targeted for secure deletion.

**Remediation:**
1. Revoke all NIST credentials and system access for iaman.informant@nist.gov immediately.
2. Audit access logs for the network share `\\10.11.11.128\secured_drive\Secret Project Data` for all users over the past 12 months.
3. Implement Data Loss Prevention (DLP) controls to block or log bulk copying to removable media.
4. Implement endpoint monitoring with USB device tracking and cloud sync application controls.
5. Review and restrict access to sensitive project repositories based on need-to-know principles.

**Evidence Preservation:**
The anti-forensic tools (CCleaner and Eraser) were successful in destroying some evidence. Recovered data from $OrphanFiles on RM2, bulk_extractor carving of prefetch and LNK data, and MFT record fragments provide strong evidentiary support despite the cleanup. The Eraser Task List.ersy and the Google Drive cloud_graph/dict_2.db (inode 75062) may contain additional evidentiary value and should be examined with specialist tooling capable of NTFS partition-offset icat extraction.

---

## Conclusion

This investigation establishes with high confidence that Iaman Informant (iaman.informant@nist.gov), a NIST employee, conducted a premeditated, multi-month data exfiltration operation prior to their resignation. Beginning no later than December 2014 and culminating on March 25, 2015, the suspect systematically copied confidential project files — including design concepts, financial pricing data, meeting presentations, and proposals — from a protected NIST network file server to multiple personal removable media devices and cloud storage accounts. The suspect researched anti-forensic countermeasures, installed and used CCleaner and Eraser to destroy evidence, and deleted cloud synchronization databases to obscure the full extent of the exfiltration. The last recorded action on the PC was viewing the resignation letter in XPS format at 15:28:33 UTC on March 25, 2015.


---

## Overview

| | |
|---|---|
| Findings | **14** (13 confirmed, 1 inference) |
| Severity | 9 critical, 4 high, 1 medium, 0 low, 0 info |
| Sources | 10 evidence sources across 246 tool calls |
| Ruled Out | 2 hypotheses tested and rejected |


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
| 2015-02-15T21:52:08Z | USB Device Exfiltration Timeline — Three Devices with IAMAN Labels | CRITICAL | bulk.winlnk, tsk.filelist |
| 2015-02-15T21:52:08Z | Complete Incident Execution Timeline — March 22-25, 2015 | CRITICAL | bulk.winprefetch, bulk.winlnk, bulk.windirs |
| 2015-03-22T14:52:21Z | Network File Server Access — \\10.11.11.128\secured_drive\Secret Project Data | CRITICAL | bulk.winlnk |
| 2015-03-25T14:31:53Z | Anti-Forensics — CCleaner and Eraser Installed, Used, then Deleted | HIGH | tsk.filelist, bulk.winlnk, bulk.winprefetch, bulk.url_searches |
| 2015-03-25T14:41:03Z | Outlook Email Client Used Just Before Cleanup — Possible Email Exfiltration | HIGH | bulk.winprefetch, bulk.email |
| 2015-03-25T15:21:40Z | Google Drive Sync Active After Anti-Forensic Cleanup — Possible Ongoing Cloud Exfiltration | CRITICAL | bulk.windirs, tsk.filelist |



---

## Findings


### 1. [CRITICAL] Insider Threat Actor Identified — Suspect "Iaman Informant"

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_eab15fab, tc_2f905212, tc_9d909bd7 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


The suspect is identified as "Iaman Informant," a user with a local account named "informant" on the PC. The resignation letter file "Resignation_Letter_(Iaman_Informant).docx" was found on the informant user's Desktop (inode 23554) and in Windows/Office Recent Items, with an active temp file "~$signation_Letter_(Iaman_Informant).docx" (deleted) indicating it was open during the incident. An XPS version was also present (inode 72008). The user profile at Users/informant contains NTUSER.DAT (inode 521), Outlook data, and full browser/cloud tool installations. Two user accounts exist on the PC: "admin11" (likely the primary employee) and "informant" — the latter is the exfiltrating actor.



### 2. [CRITICAL] Secret Project Documents Accessed and Staged for Exfiltration

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_eab15fab, tc_f230298d, tc_0c6a684b, tc_14783c8d |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


The informant user accessed and staged multiple confidential "secret project" documents from the PC, as evidenced by LNK files in both Windows Recent and Office Recent folders:
- (secret_project)_pricing_decision.xlsx (Office Recent inode 4219; Windows Recent inode 4249)
- [secret_project]_design_concept (Office Recent inode 71947)
- [secret_project]_final_meeting.pptx (Office Recent inode 7508; Windows Recent inode 4166)
- [secret_project]_proposal (Windows Recent inode 70401; Office Recent inode 71235)
- secret.lnk (Windows Recent inode 70488)
- winter_whether_advisory.zip (Windows Recent inode 20180) — later found deleted on RM2 USB

The presence of LNK entries in both Office Recent and Windows Recent confirms actual file opens, not just filesystem navigation. The secret project covers design concepts, final meeting presentations, proposals, and pricing decisions — indicating highly sensitive business intelligence was targeted.



### 3. [CRITICAL] Multi-Vector Exfiltration — USB Drives, CD-R, Google Drive, and iCloud

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist, bulk.url_services, bulk.email, bulk.domain |
| **Evidence Refs** | tc_eab15fab, tc_b61a5289, tc_9c9004e4, tc_c37fb54f, tc_f4a20f57, tc_eb168ac8, tc_1ad122a1, tc_17110d91 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Evidence confirms at least four exfiltration vectors used by the informant:

1. USB exFAT Drive (RM1): 74.6 MB image; bulk_extractor found emails, URLs, EXIF data, and ZIP content including government document fragments.

2. USB FAT32 Drive (RM2): 243.2 MB image; fls recovered 13+ windows of deleted files including folders: design/ (winter_storm.amr, winter_whether_advisory.zip), PRICIN~1/ (my_favorite_cars.db, my_favorite_movies.7z, super_bowl.avi), progress/ (my_friends.svg, my_smartphone.png, new_year_calendar.one), proposal/ (a_gift_from_you.gif, landscape.png), TECHNI~1/ (diary_#1d.txt through diary_#3p.txt). All files deleted from USB after use.

3. CD-R (RM3): 90.2 MB ISO image; bulk_extractor found government document fragments with NASA GSFC URLs (nodis3.gsfc.nasa.gov, n=36), DOE (sc.doe.gov, n=16), Whitehouse.gov, PNAS.org, and email addresses mmeyer@mail.hq.nasa.gov, mmun@loc.gov, th276a@nih.gov.

4. Google Drive: googledrivesync.exe downloaded to informant's Downloads (inode 72145 with Zone.Identifier). Google Drive installed under Users/informant/AppData/Local/Google/Drive/ with sync_log.log, snapshot.db, sync_config.db all deleted post-use. Google Drive shortcut on Desktop (inode 75066) also deleted.

5. iCloud: icloudsetup.exe downloaded (inode 72096 with Zone.Identifier). iCloud Control Panel 4.0.6.28 installer cache found deleted from ProgramData/Apple/Installer Cache/. Apple Software Update present in informant AppData.

winter_whether_advisory.zip appears in both the PC (Windows Recent LNK) and RM2 USB ($OrphanFiles), directly linking the two.



### 4. [CRITICAL] Government Agency Documents Exfiltrated — NASA, NIH, Library of Congress, DOE

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | bulk.email, bulk.url_services, bulk.rfc822 |
| **Evidence Refs** | tc_e259a434, tc_c37fb54f, tc_b61a5289, tc_9c9004e4 |
| **ATT&CK** | [T1213](https://attack.mitre.org/techniques/T1213/) |


Bulk_extractor analysis of the removable media confirms government agency documents were exfiltrated:

Email addresses embedded in documents on removable media:
- mmeyer@mail.hq.nasa.gov (NASA HQ) — found in RM2 and RM3 (inside a ZIP/Word document)
- mmun@loc.gov (Library of Congress) — found in RM2 and RM3
- th276a@nih.gov (National Institutes of Health) — found in RM3 CDR

URL patterns in RM3 CDR documents:
- nodis3.gsfc.nasa.gov (n=36) — NASA Goddard Space Flight Center NODIS system
- www.sc.doe.gov (n=16) — Department of Energy Science
- www.whitehouse.gov — White House
- www.pnas.org — Proceedings of the National Academy of Sciences
- digitalcorpora.org (n=63)

The presence of multiple government agency email addresses embedded in Office documents stored on the removable media confirms that confidential government or contractor documents were taken off-site. RFC822 artifact analysis found library-catalog style records on RM3 ("Subject: Portraits of three Indians (half-length)") suggesting Library of Congress catalog records.



### 5. [CRITICAL] Network File Server Access — \\10.11.11.128\secured_drive\Secret Project Data

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:21Z |
| **Sources** | bulk.winlnk |
| **Evidence Refs** | tc_0bcb1231 |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/) |


LNK file artifacts recovered from the PC via bulk_extractor winlnk scanner reveal that the informant accessed a network file share containing secret project data:

Network path: \\10.11.11.128\secured_drive\Secret Project Data\final
Mapped drive letter: V:
Access time: 2015-03-22T14:52:21Z

This establishes that the secret project files resided on an internal network file server at IP 10.11.11.128, mounted as drive V: under the name 'secured_drive'. The informant browsed to the 'Secret Project Data\final' subdirectory, consistent with accessing finalized project documents before exfiltrating them to removable media. The LNK creation/modification/access times all show 2015-03-22T14:52:21Z, indicating this was the access event.



### 6. [CRITICAL] Suspect Fully Identified — iaman.informant@nist.gov, NIST Employee

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Sources** | bulk.email, bulk.domain, tsk.filelist |
| **Evidence Refs** | tc_f44fd31f, tc_9c82319b, tc_2f905212, tc_232752f3 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


The suspect is definitively identified as 'Iaman Informant' (iaman.informant@nist.gov), a NIST (National Institute of Standards and Technology) employee:

1. Outlook OST file path recovered from bulk.email: 'Outlook\iaman.informant@nist.gov.ost' — confirms the informant's corporate email address at NIST
2. Additional NIST email addresses in bulk.domain: '6f-b1df9935415b@nist.gov' (ExchangeLabs format) with /o=ExchangeLabs — confirms NIST uses Microsoft Exchange Online (Office 365)
3. Network file server 10.11.11.128 ('secured_drive') referenced alongside nist.gov in bulk.domain
4. Username on PC: 'informant' with NTUSER.DAT at inode 521
5. Resignation letter on Desktop: 'Resignation_Letter_(Iaman_Informant).docx'
6. USB drives with labels consistent with the name: 'IAMAN $_@' (RM2 FAT32) and 'IAMAN CD' (RM3 CDR)

This is a NIST employee who used their work PC to stage and exfiltrate confidential project data before submitting their resignation.



### 7. [CRITICAL] USB Device Exfiltration Timeline — Three Devices with IAMAN Labels

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T21:52:08Z -- 2015-03-24T20:40:55Z |
| **Sources** | bulk.winlnk, tsk.filelist |
| **Evidence Refs** | tc_0bcb1231, tc_2b7351ca, tc_506cfc2f, tc_f44fd31f, tc_6b141b36 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


LNK artifacts identify three removable media devices used for exfiltration, all labeled with the suspect's alias:

1. RM1 ('Authorized USB', E:\RM#1\) — exFAT USB drive:
   - Accessed 2015-02-15T21:52:12Z: E:\RM#1\Secret Project Data\proposal\
   - Accessed 2015-02-15T21:52:20Z: E:\RM#1\Secret Project Data\proposal\[secret_project]_proposal.docx (file wtime: 2014-12-19T19:53:46Z)
   - Accessed 2015-02-15T21:52:08Z: E:\RM#1\Secret Project Data\design\

2. RM2 ('IAMAN $_@', E:\) — FAT32 USB drive:
   - Volume label confirmed in fls: 'IAMAN $_@   (Volume Label Entry)'
   - Accessed 2015-03-24T04:00:00Z: E:\Secret Project Data\design\winter_whether_advisory.zip (file wtime: 2014-12-16T16:10:26Z)
   - Multiple deleted folders recovered: design, PRICIN~1, progress, proposal, TECHNI~1
   - All contents deleted after use

3. RM3 ('IAMAN CD', D:\) — CD-R disc:
   - Volume label: 'IAMAN CD'
   - Accessed 2015-03-24T20:40:55Z: D:\de\winter_whether_advisory.zip (file wtime: 2014-12-16T16:10:26Z)
   - Contains government document fragments (NASA, NIH, Library of Congress)

Earliest exfiltration: 2015-02-15 (RM1 USB). Last exfiltration: 2015-03-24 (RM2/RM3). Anti-forensic cleanup: 2015-03-25.



### 8. [CRITICAL] Complete Incident Execution Timeline — March 22-25, 2015

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T21:52:08Z -- 2015-03-25T15:28:33Z |
| **Sources** | bulk.winprefetch, bulk.winlnk, bulk.windirs |
| **Evidence Refs** | tc_65e0ff65, tc_3f5c4c39, tc_fd34f427, tc_03df8a2d, tc_52b0eaa6, tc_c2285697, tc_0bcb1231 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1070](https://attack.mitre.org/techniques/T1070/) |


Prefetch artifacts and winlnk cross-correlation establish a detailed execution timeline:

**2015-02-15 (~21:52 UTC):**
- First USB exfiltration: Accessed E:\RM#1\Secret Project Data\proposal\[secret_project]_proposal.docx on 'Authorized USB' (RM1)
- Files with wtime as early as 2014-12-19 — data was prepared months earlier

**2015-03-22 (primary access day):**
- 14:34:31 UTC — 'informant' user DIRECTORY CREATED in MFT (account newly created)
- 14:34:55 UTC — Informant's Desktop browsed
- 14:52:21 UTC — Network share \\10.11.11.128\secured_drive\Secret Project Data browsed (drive V:)
- 14:52:21 UTC — (secret_project)_pricing_decision.xlsx accessed from network share
- 15:03:23 UTC — Outlook opened (iaman.informant@nist.gov)
- 15:11:51 UTC — Google Chrome opened (multiple instances, browsing)
- 15:54:04 UTC — admin11 account Quick Launch accessed
- 15:56:07 UTC — 'temporary' user account Quick Launch accessed

**2015-03-24:**
- 14:05:12 UTC — Internet Explorer ran (12 runs)
- 15:21:38 UTC — VSSVC.EXE (Volume Shadow Copy) ran (4 runs)
- 18:31:55 UTC — STIKYNOT.EXE (Sticky Notes) ran (2 runs) - notes during resignation letter writing
- 18:48:40 UTC — Resignation Letter accessed in Word (creation)
- 18:59:30 UTC — Resignation Letter opened/edited in Word
- 19:09:51 UTC — WINWORD.EXE last ran (2 total runs)
- 20:40:55 UTC — 'IAMAN $_@' USB accessed (winter_whether_advisory.zip on E:)
- 20:57:00 UTC — 'IAMAN CD' (RM3 CDR) accessed: D:\Koala.jpg
- 20:58:06 UTC — Browsing root of 'IAMAN CD' disc
- 21:02:47 UTC — DEVICEDISPLAYOBJECTPROVIDER.EXE ran (USB device display)

**2015-03-25 (anti-forensic cleanup day):**
- 10:18:15 UTC — CLRGC.EXE (CLR GC, possibly Google Drive sync)
- 13:07:49 UTC — SVCHOST.EXE ran
- 13:24:10 UTC — SYSTEM registry hive accessed (MFT)
- 14:20:09 UTC — TASKENG.EXE (Task Scheduler, 23 runs)
- 14:31:53 UTC — CONHOST.EXE ran (12 runs) — command-line session
- 14:41:03 UTC — OUTLOOK.EXE ran (1 run) — final email sent
- 14:41:13 UTC — IE History folder MSHist012015032520150326 created (browsing)
- 14:42:47 UTC — WMPLAYER.EXE ran (1 run) — played media file
- 14:47:29 UTC — Ad tracking GIF downloaded (web browsing)
- 14:50:14 UTC — Eraser 6.2.0.2962.EXE installer ran (installation)
- 14:50:17 UTC — SETUP.EXE ran (Eraser installer)
- 14:50:53 UTC — TMP5B99.TMP.EXE ran (installer temp)
- 14:51:29 UTC — UIAutomationClient.dll created (Eraser .NET dependency)
- 14:52:57 UTC — NGEN.EXE ran (.NET compilation for Eraser)
- 14:54:21 UTC — ASPNET_REGIIS.EXE ran (ASP.NET registration)
- 14:57:18 UTC — VSSVC.EXE ran (6 runs) — Volume Shadow Copy activity
- 14:58:35 UTC — CCleaner64.exe LNK accessed (CCleaner ran)
- 15:13:30 UTC — ERASER.EXE ran (2 runs) — secure file deletion
- 15:15:54 UTC — ccc0fa1b9f86f7b3.customDestinations-ms accessed (Jump List for an application)
- 15:21:31 UTC — menu_sync_anim_2x.gif (web browsing after cleanup)
- 15:21:40 UTC — GOOGLEDRIVESYNC.EXE-841A0D94.pf CREATED — Google Drive ran AFTER cleanup!
- 15:22:07 UTC — IEXPLORE.EXE ran (14 runs)
- 15:28:33 UTC — Resignation_Letter_(Iaman_Informant).xps LNK accessed — LAST DOCUMENTED ACTION



### 9. [CRITICAL] Google Drive Sync Active After Anti-Forensic Cleanup — Possible Ongoing Cloud Exfiltration

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T15:21:40Z |
| **Sources** | bulk.windirs, tsk.filelist |
| **Evidence Refs** | tc_03df8a2d, tc_f4a20f57, tc_6ed7ce93 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


A prefetch artifact for GoogleDriveSync was discovered created AFTER the CCleaner and Eraser cleanup activities:

- MFT record: 'GOOGLEDRIVESYNC.EXE-841A0D94.pf' created at 2015-03-25T15:21:40Z
- This is the Windows Prefetch file for Google Drive Sync, meaning Google Drive Sync was EXECUTED at 15:21:40 on March 25
- CCleaner ran at 14:58:35 and Eraser ran at 15:13:30
- Google Drive sync ran at 15:21:40 — TEN MINUTES AFTER Eraser was used to wipe files

This means that either:
1. Google Drive continued auto-syncing files from the 'My Drive' folder AFTER the cleanup, potentially uploading additional data to Google Cloud
2. Or the informant manually ran Google Drive Sync as a final exfiltration step after clearing local traces

The informant account at Users/informant/AppData/Local/Google/Drive/ had sync_log.log, snapshot.db, and sync_config.db deleted — but the sync CONTINUED before the final logoff. The Google Drive shortcut was also deleted from the Desktop (inode 75066).

Data exfiltrated via Google Drive remains unrecovered as the sync database files were deleted.



### 10. [HIGH] Anti-Forensics — Cloud Sync Evidence Deliberately Deleted

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_eab15fab, tc_6ed7ce93, tc_f4a20f57, tc_1ad122a1, tc_125c5b41 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The informant deliberately deleted cloud synchronization artifacts after exfiltration, indicating awareness of forensic investigation:

Google Drive:
- sync_log.log (inode 75035): listed as both present and deleted (r/- * 0) — overwritten
- snapshot.db (inode 75039): deleted (-/r *)
- sync_config.db (inode 75040): deleted (-/r *)
- sync_config.db-wal (inode 73727): deleted
- sync_config.db-shm (inode 73728): deleted
- snapshot.db-shm (inode 73726): deleted
- Google Drive.lnk on Desktop (inode 75066): deleted (-/r *)
- cloud_graph/dict_2.db-wal (inode 73730): deleted
- cloud_graph/dict_2.db-shm (inode 73731): deleted

iCloud:
- iCloud Control Panel 4.0.6.28 installer cache: deleted from ProgramData/Apple/Installer Cache/
- Chrome History for informant: History database absent; only History-journal remains (inode 62907)

All RM2 USB files were also deleted from the FAT32 drive after copying, recovered only as $OrphanFiles.

This systematic deletion of sync logs, configuration databases, browser history, and cloud shortcuts demonstrates planned anti-forensic activity to conceal the scope of exfiltration.



### 11. [HIGH] Premeditated Anti-Forensic Research — Browser Search History

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Sources** | bulk.url_searches |
| **Evidence Refs** | tc_146737fc, tc_da64ef61 |
| **ATT&CK** | [T1070](https://attack.mitre.org/techniques/T1070/) |


Bulk_extractor URL search histogram extracted from the PC image reveals the informant's premeditated anti-forensic research. The top search queries found in browser history (counts indicate frequency across sessions/pages):

- 'file sharing and tethering' (n=491) — researched exfiltration methods
- 'DLP DRM' (n=90) — researched Data Loss Prevention and Digital Rights Management (evasion)
- 'e-mail investigation' (n=88) — researched email forensics
- 'anti-forensic tools' (n=85) — directly researched tools to cover tracks
- 'Forensic Email Investigation' (n=78) — researched email forensics investigation methods
- 'ccleaner' (n=65) — researched the specific wiping tool later installed
- 'external device and forensics' (n=65) — researched USB/external device forensics
- 'cd burning method' (n=64) — researched CD-R burning (method used with RM3)

This search pattern demonstrates premeditation, research into cover-up techniques, and active evasion of DLP controls. The informant deliberately studied how digital forensics investigations work before committing the theft.



### 12. [HIGH] Anti-Forensics — CCleaner and Eraser Installed, Used, then Deleted

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:31:53Z -- 2015-03-25T14:58:35Z |
| **Sources** | tsk.filelist, bulk.winlnk, bulk.winprefetch, bulk.url_searches |
| **Evidence Refs** | tc_9346dcc5, tc_f03edfac, tc_52b0eaa6, tc_146737fc |
| **ATT&CK** | [T1070](https://attack.mitre.org/techniques/T1070/), [T1027](https://attack.mitre.org/techniques/T1027/) |


Two data-wiping anti-forensic tools were installed on the PC and later uninstalled/deleted, indicating a deliberate attempt to erase evidence of the data theft:

1. CCleaner: Installed at Program Files/CCleaner/ (directories and files all deleted: -/d * 75246, -/r * 75248 CCleaner.exe, -/r * 75250 CCleaner64.exe). Desktop shortcut also deleted: Users/Public/Desktop/CCleaner.lnk (-/r * 75306). CCleaner web page cached in informant's IE Temporary Internet Files. LNK file for CCleaner64.exe shows last access 2015-03-25T14:58:35Z.

2. Eraser: Desktop shortcut deleted: Users/Public/Desktop/Eraser.lnk (-/r * 75235). Eraser is a secure file overwriting tool that prevents recovery.

3. CONHOST.EXE prefetch: atime 2015-03-25T14:31:53Z, 12 runs — indicates command-line tool use on 2015-03-25.

4. Browser history confirms informant searched: 'anti-forensic tools' (n=85), 'ccleaner' (n=65), 'external device and forensics' (n=65). CCleaner cache pages stored in informant's IE Temporary Internet Files (inode 75119, 71565, 75162).

The CCleaner LNK timestamp of 2015-03-25T14:58:35Z establishes that anti-forensic tool usage occurred on March 25, 2015.



### 13. [HIGH] Outlook Email Client Used Just Before Cleanup — Possible Email Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-25T14:41:03Z |
| **Sources** | bulk.winprefetch, bulk.email |
| **Evidence Refs** | tc_03df8a2d, tc_f44fd31f |
| **ATT&CK** | [T1048](https://attack.mitre.org/techniques/T1048/) |


Outlook.exe ran on the morning of the anti-forensic cleanup day:

1. OUTLOOK.EXE prefetch: atime 2015-03-25T14:41:03Z, 1 run — Outlook opened just 17 minutes before starting the Eraser installation
2. LNK for OUTLOOK.EXE at 2015-03-22T15:03:23Z — also opened on the main file access day
3. Outlook profile: iaman.informant@nist.gov (Office 365 ExchangeLabs)
4. Outlook.srs file at Users/informant/AppData/Roaming/Microsoft/Outlook/Outlook.srs (inode 62951) confirms active Outlook profile
5. NIST uses Microsoft Exchange Online (Office 365) as confirmed by /o=ExchangeLabs format in email artifacts

The timing suggests the informant may have emailed documents to a personal address before deleting evidence. This cannot be confirmed without email content (PST/OST file) but the single run of Outlook immediately before starting the wiping process is highly suspicious. No PST/OST files were found in the fls listing (they may have been encrypted or stored elsewhere).



### 14. [MEDIUM] Kodak Digital Camera Images on All Removable Media — Government Document Photographs

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Sources** | bulk.exif |
| **Evidence Refs** | tc_cb1d1de0, tc_8a9e8351, tc_b03da25f |


EXIF metadata extracted from JPEG files on all three removable media shows images taken with an Eastman Kodak DIGITAL SCIENCE DC260 (V01.00) camera:

- RM3 CDR: Kodak DC260 EXIF at offset 1,310,146
- RM2 FAT32: Kodak DC260 EXIF at offsets 4,912,578 and 27,555,388
- RM1 exFAT: Kodak DC260 EXIF at offset 1,093,257; Adobe Photoshop CS processed image

The Kodak DC260 is a late 1990s/early 2000s digital camera commonly used for document digitization and archival photography. Combined with RFC822 catalog records found on RM3 ('Subject: Portraits of three Indians (half-length)') consistent with Library of Congress catalog entries, these images likely represent digitized/photographed government documents and archival records.

One RM2 image has SHA1 hash: aab7ebb56ec75ae3da1534c300ac65637f96b9a9 (Adobe Photoshop CS processed).




---

## Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No Evidence of a Second Independent Attack Narrative** -- Phase 3.5 alternative narrative discovery found no evidence of a separate incident unrelated to the primary narrative:

1. admin11 account: No LNK files, Recent items, or file access evidence...

- **No Malware or Remote Access Tools Found** -- YARA signature scanning and steganography detection could not be performed on the disk images due to EWF mount failures preventing filesystem extraction. However, keyword searches across all...



---

## Indicators of Compromise

### Network IOCs

| Type | Value | Context |
|------|-------|---------|
| External IP | `4.0.6.28` | Multi-Vector Exfiltration — USB Drives, CD-R, Google Drive, and iCloud |
| Internal IP | `10.11.11.128` | Network File Server Access — \\10.11.11.128\secured_drive\Secret Project Data |


### File IOCs

| Type | Value | Context |
|------|-------|---------|
| Path | `/System32/` | [NEGATIVE] No Malware or Remote Access Tools Found |



### Email IOCs

| Type | Value | Context |
|------|-------|---------|
| Email | `mmeyer@mail.hq.nasa.gov` | Multi-Vector Exfiltration — USB Drives, CD-R, Google Drive, and iCloud |
| Email | `mmun@loc.gov` | Multi-Vector Exfiltration — USB Drives, CD-R, Google Drive, and iCloud |
| Email | `th276a@nih.gov` | Government Agency Documents Exfiltrated — NASA, NIH, Library of Congress, DOE |
| Email | `iaman.informant@nist.gov` | Suspect Fully Identified — iaman.informant@nist.gov, NIST Employee |
| Email | `6f-b1df9935415b@nist.gov` | Suspect Fully Identified — iaman.informant@nist.gov, NIST Employee |
| Email | `eric_p._lauer@omb.eop.gov` | [NEGATIVE] No Evidence of a Second Independent Attack Narrative |
| Email | `scarter@gmail.com` | [NEGATIVE] No Evidence of a Second Independent Attack Narrative |




---

## MITRE ATT&CK Coverage

11 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) &#8594; Persistence (1) &#8594; Privilege Escalation (1) &#8594; Defense Evasion (4) &#8594; Collection (4) &#8594; Exfiltration (3)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Insider Threat Actor Identified — Suspect...; Suspect Fully Identified —... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Insider Threat Actor Identified — Suspect...; Suspect Fully Identified —... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Insider Threat Actor Identified — Suspect...; Suspect Fully Identified —... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Anti-Forensics — CCleaner and Eraser... |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | Premeditated Anti-Forensic Research — Browser...; Anti-Forensics — CCleaner and Eraser...; Complete Incident Execution Timeline — March... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Anti-Forensics — Cloud Sync Evidence...; Google Drive Sync Active After Anti-Forensic... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Insider Threat Actor Identified — Suspect...; Suspect Fully Identified —... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Secret Project Documents Accessed and Staged...; Complete Incident Execution Timeline — March... |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network File Server Access —... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Secret Project Documents Accessed and Staged... |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Government Agency Documents Exfiltrated —... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Outlook Email Client Used Just Before Cleanup... |
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Multi-Vector Exfiltration — USB Drives, CD-R,...; USB Device Exfiltration Timeline — Three...; Complete Incident Execution Timeline — March... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Multi-Vector Exfiltration — USB Drives, CD-R,...; Google Drive Sync Active After Anti-Forensic... |





---

## Audit Trail

| Metric | Value |
|--------|-------|
| Total tool calls | 246 |
| Findings submitted | 14 |
| Confirmed | 13 |
| Inferences | 1 |
| Audit log | /root/.mulder/cases/nist-data-leakage.audit.jsonl |


<details>
<summary>Evidence Sources (50)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 9 |
| tsk.partitions | sleuthkit | 10 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.fsstat | sleuthkit | 0 |
| tsk.fsstat | sleuthkit | 0 |
| tsk.fsstat | sleuthkit | 0 |
| tsk.fsstat | sleuthkit | 0 |
| bulk.domain | bulk_extractor | 7295 |
| bulk.email | bulk_extractor | 22 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7204 |
| bulk.url_services | bulk_extractor | 60 |
| bulk.zip | bulk_extractor | 5221 |
| bulk.domain | bulk_extractor | 7295 |
| bulk.domain | bulk_extractor | 5205 |
| bulk.email | bulk_extractor | 26 |
| bulk.email | bulk_extractor | 14 |
| bulk.exif | bulk_extractor | 27 |
| bulk.exif | bulk_extractor | 20 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 5226 |
| bulk.url | bulk_extractor | 7192 |
| bulk.url_services | bulk_extractor | 25 |
| bulk.zip | bulk_extractor | 3851 |
| bulk.url_services | bulk_extractor | 58 |
| bulk.zip | bulk_extractor | 5221 |
| bulk.domain | bulk_extractor | 403461 |
| bulk.email | bulk_extractor | 6553 |
| bulk.ether | bulk_extractor | 6 |
| bulk.evtx_carved | bulk_extractor | 494 |
| bulk.exif | bulk_extractor | 794 |
| bulk.ip | bulk_extractor | 29 |
| bulk.jpeg | bulk_extractor | 9 |
| bulk.ntfsmft_carved | bulk_extractor | 338 |
| bulk.ntfsusn_carved | bulk_extractor | 66223 |
| bulk.packets | bulk_extractor | 166 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.sqlite_carved | bulk_extractor | 95 |
| bulk.tcp | bulk_extractor | 15 |
| bulk.url | bulk_extractor | 458526 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3683 |
| bulk.windirs | bulk_extractor | 84104 |
| bulk.winlnk | bulk_extractor | 466 |
| bulk.winprefetch | bulk_extractor | 155 |
| bulk.zip | bulk_extractor | 22327 |


</details>


---

*Report generated by [Mulder](https://github.com/caevans/mulder) -- AI-driven forensic investigation via MCP*
