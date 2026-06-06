# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-06-06T20:44:56.512486+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 88 evidence sources (42 disk, 46 other) | 723 tool calls | 1.7 hours
**Results:** 33 findings (15 high) | 29 confirmed, 4 inference
**Timeline:** 2003-09-24 to 2015-03-26

**Attack Lifecycle:**
- **Initial Access / Deployment** (2014-10-31 to 2015-03-26): Premeditated Anti-Forensics Research: Search History Reveals Deliberate Planning of Data Leakage and Evidence Destruction (+13 related)
- **Persistence** (2014-12-04 to 2015-03-24): Document Metadata Contains University of Maryland (UMD) References (+4 related)
- **Command and Control** (2003-09-24 to 2015-03-26): RM2 Personal Image Files with EXIF Metadata — Kodak Camera Photos from 2003-2013 (+2 related)
- **Credential Access** (2014-12-16 to 2015-02-15): RM2 Contains Disguised Copies of Secret Project Documents with Falsified Extensions (+1 related)
- **Defense Evasion / Anti-Forensics** (2015-03-26): RM3 Media Identification: CD-ROM with UDF Filesystem

**Tools:** search (205), get_raw_output (86), extract_file_by_inode (46), submit_finding (41), open_case (28). SHA-256 hashes recorded for all evidence.



---

## Forensic Soundness and Evidence Integrity

Analysis was executed via a read-only Model Context Protocol (MCP) server
mapped to the SANS SIFT toolchain. The MCP architecture enforces structural
evidence protection: original evidence files were mounted as read-only
volumes, all tool interactions are typed functions (no shell access), and
every finding is validated against the append-only audit log before
acceptance.

8 evidence files were cryptographically
validated via SHA-256 hashes computed at ingestion and verified against the
case database.

723 tool calls were executed across 33
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# CFREDS 2015 Data Leakage — Digital Forensic Investigation Report

## Background

This investigation was initiated in response to a suspected insider data leakage incident involving the unauthorized exfiltration of proprietary research documents from a government workstation. The forensic examination encompassed four evidence items acquired as EnCase E01 disk images: a Windows 7 workstation (informant-PC), two USB flash drives (RM1 and RM2), and one CD-ROM disc (RM3). The investigation indexed 33 distinct evidence sources across 723 forensic tool invocations, producing 33 findings — 0 critical, 15 high, 7 medium, and 0 negative (ruled-out). Of these, 29 were confirmed through multi-source corroboration and 4 were assessed as inferences supported by circumstantial evidence. The findings map to 12 distinct MITRE ATT&CK techniques.

The host workstation is a standalone Windows 7 Professional (64-bit) machine named "informant-PC" in a WORKGROUP configuration. The system had six user accounts, with the primary account "informant" (RID 1000) belonging to an individual identified as "Iaman Informant" through a resignation letter found on the desktop and the email address iaman.informant@nist.gov discovered in Outlook OST file references and bulk_extractor carved data. The organizational affiliation with the National Institute of Standards and Technology (NIST), combined with the resignation letter and anti-forensics activity, established the context for this insider threat investigation. The system ran Microsoft Office (Word, Outlook, XPS viewer), Google Drive sync, and Internet Explorer, with evidence of both local document processing and cloud synchronization. Removable media device RM1 is a 3.7 GB exFAT-formatted USB drive labeled "Authorized USB" (volume serial 5c75-4d3e). RM2 is a dual-partition USB device containing both NTFS and FAT32 volumes, with the FAT32 partition labeled "IAMAN $_@" — a truncation of the suspect's name. RM3 is a UDF-formatted CD-ROM created on March 26, 2015, one day after the final cleanup activity observed on the PC.

## Incident Timeline

The incident unfolded over approximately five months, from late October 2014 through late March 2015, and can be reconstructed across six distinct operational phases through cross-correlation of filesystem timestamps, registry artifacts, ShimCache entries, EVTX event logs, and search history.

**Phase 1 — Research and Planning (October 2014 – January 2015).** The earliest datable evidence of the suspect's intent is found in browser search history carved by bulk_extractor, with URL timestamps dating to at least October 31, 2014. The suspect conducted extensive research into data leakage techniques, searching for "information leakage cases" (47 hits), "how to leak a secret" (6 hits), "intellectual property theft" (6 hits), and "data leakage methods." Concurrently, the suspect researched exfiltration channels, with "file sharing and tethering" generating 491 search hits — the most-searched term in the entire browsing history. Specific cloud services were evaluated, including Google Drive (10 hits) and Apple iCloud (1 hit). The suspect also studied anti-forensics methodology through searches for "anti-forensic tools" (85 hits), "digital forensics," and extensive visits to forensicswiki.org (45 URL matches). Critically, the suspect researched Windows forensic artifacts — "what is windows system artifacts" (79 hits), "windows event logs" (61 hits), and "external device and forensics" (65 hits) — demonstrating awareness of the very evidence sources that would later be used to reconstruct these events. The Eraser secure deletion tool binary (Eraser.exe) carries a LastModified date of January 12, 2015 in ShimCache, establishing its presence on the system by that date.

**Phase 2 — Initial Exfiltration via USB (February 15, 2015).** On Sunday, February 15, 2015, at 16:51:38 UTC, the suspect executed a bulk copy operation transferring five proprietary "Secret Project" documents — three design presentations and two proposal documents totaling approximately 74 MB — to the USB media. The filesystem timeline on RM1 records all five files and their directory structure being written between 16:51:38 and 16:52:20, a 42-second window consistent with a single drag-and-drop or copy operation. Simultaneously, the same documents were copied to RM2's NTFS partition with identical timestamps and original filenames. The RM2 FAT32 partition received copies of at least four of the same documents, but with deliberately falsified filenames and extensions: [secret_project]_detailed_proposal.docx became "a_gift_from_you.gif," [secret_project]_detailed_design.pptx became "winter_whether_advisory.zip," [secret_project]_revised_points.ppt became "winter_storm.amr," and [secret_project]_proposal.docx became "landscape.png." Byte-for-byte file size matching (35,226,880; 16,381,123; 14,547,968; and 6,484,502 bytes respectively) and internal OOXML ZIP structures (word/document.xml, ppt/presentation.xml) confirmed these were the same Office documents despite the disguised extensions. The modification timestamps on the FAT32 partition are consistently one hour later than the NTFS timestamps, consistent with FAT32 storing local time versus NTFS storing UTC in a UTC+1 timezone environment.

**Phase 3 — Cloud Sync Deployment (February 19, 2015 onward).** Four days after the USB exfiltration, on February 19, 2015, Google Drive sync (googledrivesync.exe) was installed and executed on the PC, as confirmed by ShimCache execution flags and binary compilation dates. A Google Drive sync folder was created at Users/informant/Google Drive/ containing a deleted file (happy_holiday.jpg) and deleted synchronization databases (snapshot.db, sync_config.db). The Prefetch file GOOGLEDRIVESYNC.EXE-841A0D94.pf corroborates execution. iCloud setup (icloudsetup.exe) was downloaded on March 23, 2015, within 20 seconds of a Google Drive sync download, suggesting the suspect was evaluating multiple cloud exfiltration channels. However, the deleted sync databases are irrecoverable, and no direct evidence of Secret Project document uploads to Google Drive was found — the cloud exfiltration channel remains likely but unconfirmed.

**Phase 4 — Evidence Review and Initial Cleanup (March 13–23, 2015).** On March 13, 2015, CCleaner 5.04 (CCleaner64.exe) was first executed, as recorded in ShimCache entry #61 with a LastModified timestamp of 11:10:26. The CCleaner uninstaller (uninst.exe) ran the same day at 13:55:38, indicating the tool was installed, used, and uninstalled within hours. CCleaner's execution effectively destroyed browser history databases, Jump Lists, LNK shortcut files, and Shellbags — all four user activity artifact categories returned zero entries from forensic parsing tools despite their underlying database files existing on disk. On March 23, 2015, the suspect connected USB Device 1 (serial 4C530012450531101593) to the PC, confirmed by USBSTOR driver installation at 18:31:10 in the System EVTX log. Earlier that day, at 14:32:20, the "Secret Project Data" directory on RM2's NTFS partition was deleted. At 14:37:52, a Word temporary file (~$ecret_project]_proposal.docx) was created on the USB, proving the suspect opened the proposal document in Microsoft Word for review. Between 16:55:17 and 16:55:37, all 22 personal image files on RM2's FAT32 partition were batch-deleted in a 20-second window.

**Phase 5 — Systematic Evidence Destruction (March 24–25, 2015).** On March 24, 2015, the suspect systematically deleted all remaining organized files on RM2's FAT32 partition between 09:54:54 and 10:00:18, including the disguised Secret Project copies and additional files in directories with truncated long filenames (PRICIN~1 and TECHNI~1, suggesting "pricing" and "technical" content). USB Device 1 was reconnected at 13:38:00, and USB Device 2 (serial 4C530012550531106501) was connected for the first time at 13:58:32 — only 20 minutes after Device 1's reconnection. The last regular file (desktop.ini) was deleted at 15:51:47, and the volume label "IAMAN $_@" was the final timestamp on the entire RM2 device at 17:02:36. On March 25, 2015, the suspect reinstalled both anti-forensics tools on the PC in rapid succession: the Eraser installer executed at 14:47:40, CCleaner at 14:48:28 (48 seconds later), and the Eraser .NET bootstrapper at 14:50:15. The System Restore point "Installed Eraser 6.2.0.2962" was created at 14:57:27, recorded in the Application EVTX log.

**Phase 6 — Final Exfiltration to Optical Media (March 26, 2015).** On March 26, 2015, at 18:35:29 UTC, a CD-ROM disc (RM3) was burned, as recorded by the ISO creation timestamp in ExifTool metadata. The disc was created using a HL-DT-ST DVD+-RW GT80N drive — a VMware virtual optical drive consistent with the informant-PC environment. The disc contains a UDF v5.13 filesystem with approximately 107.5 MB of content, including a government IT governance DOCX document with embedded IREAP/UMER references matching the Secret Project documents. This final exfiltration occurred one day after the cleanup tools were reinstalled, creating a tamper-proof, read-only copy of data on media that the suspect had specifically researched for its ability to pass physical security checkpoints ("security checkpoint cd-r" search query).

## Key Findings

**Proprietary Document Exfiltration.** The core finding of this investigation is the unauthorized transfer of five proprietary research documents related to the University of Maryland's IREAP/UMER project (Institute for Research in Electronics and Applied Physics / University of Maryland Electron Ring) to removable media. The documents comprise three design presentations ([secret_project]_design_concept.ppt, [secret_project]_detailed_design.pptx, [secret_project]_revised_points.ppt) and two proposal documents ([secret_project]_detailed_proposal.docx, [secret_project]_proposal.docx), with modification dates spanning December 4, 2014 through January 23, 2015. These documents were found in their original form on RM1 and RM2's NTFS partition, in disguised form on RM2's FAT32 partition, and as carved content references on RM3 — four independent copies across three physical media devices. No encryption, compression, or password protection was applied to any copy; the data was exfiltrated in its original, unprotected format. The documents were transferred via direct file copy rather than through archive staging, and no evidence of archive or encryption tool execution was found in ShimCache's 292 entries.

**Deliberate File Masquerading on RM2.** The presence of disguised copies on RM2's FAT32 partition represents a deliberate concealment effort. The suspect renamed the four largest Secret Project documents with innocuous filenames ("a_gift_from_you," "winter_storm," "landscape") and applied false file extensions (.gif, .amr, .png, .zip) that would cause the files to appear as personal media rather than Office documents in a casual inspection. Internal OOXML ZIP structures (word/document.xml, ppt/presentation.xml) confirmed the true file type. An additional twelve deleted files in themed directories (PRICIN~1, progress, TECHNI~1) with similar naming patterns may represent additional exfiltrated workplace data, but file header analysis was not possible due to extraction tool limitations.

**Premeditated Anti-Forensics Campaign.** The suspect's search history, corroborated by subsequent tool execution across multiple evidence sources, demonstrates premeditation rather than opportunistic data theft. The research progressed systematically from data leakage methodology to exfiltration channel evaluation, anti-forensics tool selection, Windows artifact awareness, and counter-investigation techniques. Each search topic maps directly to actions subsequently taken: "anti-forensic tools" preceded Eraser and CCleaner deployment; "google drive" and "cloud storage" preceded Google Drive sync installation; "cd burning method" preceded RM3 creation; "external device and forensics" preceded the careful multi-device cleanup. The suspect's awareness of forensic examination procedures is evidenced by searches for "investigation on windows machine" (64 hits), "e-mail investigation" (88 hits), and visits to the NIJ Digital Evidence portal.

**Systematic Artifact Destruction.** CCleaner's execution effectively destroyed four categories of user activity artifacts — browser history, Jump Lists, LNK files, and Shellbags — all of which returned zero entries from forensic parsing tools despite their underlying database files existing on disk. This represents the most impactful anti-forensics outcome of the case, as these artifacts would have provided timestamp correlation for search history, direct USB-to-file access linkage through volume serial numbers in LNK files, and folder navigation records through Shellbags. The Eraser secure deletion tool was deployed to destroy file content and metadata, with the PC's MFT containing zero surviving references to any Secret Project document filename — consistent with either successful secure deletion of local copies or direct network-to-USB transfer without local storage. Prefetch files, registry hives (USBSTOR, ShimCache, SAM), EVTX event logs, and MFT structural entries survived the cleanup, providing the primary evidence basis for this investigation.

**Cross-Media Document Provenance.** IREAP/UMER URL references (www.ireap.umd.edu/umer, www.umer.umd.edu) and digitalcorpora.org/corpora/govdocs markers appear on all four evidence items — RM1, RM2, the PC, and RM3 — establishing a complete data provenance chain. The Kodak DC260 camera model appears in EXIF metadata on both RM2 (personal photographs) and RM3 (embedded document images), creating an additional cross-media correlation. These consistent markers across independent evidence items confirm that the same document corpus was transferred through multiple exfiltration vectors.

## Threat Intelligence and Attribution

This incident represents a classic insider threat case with no indicators of external compromise, remote access, or lateral movement. Composite analysis across lateral movement, defense evasion, file staging, and persistence sources returned zero malicious indicators, confirming the absence of an external threat actor.

The behavioral profile is consistent with a motivated insider with authorized access who leveraged legitimate tools and techniques rather than exploiting technical vulnerabilities. The MITRE ATT&CK technique mapping spans T1078.001 (Valid Accounts: Default Accounts) for initial access, T1005 (Data from Local System) and T1052.001 (Exfiltration Over Physical Medium: Removable Media) for collection and exfiltration, T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage) for the cloud vector, T1036.008 (Masquerade: Masquerade File Type) and T1027 (Obfuscated Files or Information) for concealment, and T1070.004 (Indicator Removal: File Deletion) and T1485 (Data Destruction) for anti-forensics.

The suspect's operational security was moderately sophisticated. The use of multiple exfiltration vectors (USB, cloud, optical media), file extension masquerading, and sequential deployment of secure deletion and system cleaning tools demonstrates planning and research. However, several critical errors undermined the anti-forensics effort: Prefetch files survived CCleaner's default cleaning profile, ShimCache preserved execution timestamps for all tools, EVTX event logs recorded USB device connections, and the physical USB media was retained with recoverable filesystem structures. The suspect's awareness of forensic methodology — evidenced by extensive research into digital forensics, Windows artifacts, and investigation procedures — did not translate into comprehensive evidence destruction.

Attribution to the user "Iaman Informant" (iaman.informant@nist.gov) is established through convergent evidence from six independent sources: the SAM registry account, the desktop resignation letter, the Outlook email profile, the RM2 volume label "IAMAN $_@," the search history patterns, and the timeline correlation between user logon events and anti-forensics activity. No evidence suggests the involvement of additional individuals, external threat actors, or a coordinated operation beyond this single insider.

## Impact Assessment

The confirmed scope of data exfiltration encompasses five proprietary research documents totaling approximately 74 MB, originating from the University of Maryland IREAP/UMER project. These documents span design concepts, detailed designs, revised technical points, and formal proposals — representing a substantial body of intellectual property covering both technical specifications and business strategy. The documents were replicated across three physical media devices (two USB drives, one CD-ROM) and potentially uploaded to Google Drive cloud storage, creating multiple uncontrolled copies outside organizational custody.

One workstation (informant-PC) was directly involved, and no lateral movement or multi-system compromise was detected. The incident is contained to a single user account operating within its authorized access scope. Credential exposure is limited to the local system; no evidence of credential theft, password harvesting, or authentication token exfiltration was observed. The suspect's NIST email credentials (iaman.informant@nist.gov) were used legitimately, and the SAM registry shows no unauthorized account creation or privilege escalation.

The anti-forensics campaign successfully destroyed browser history, user activity artifacts (Jump Lists, LNK files, Shellbags), and potentially local copies of the exfiltrated documents. While these gaps limit the ability to establish the full scope of data accessed or transferred (particularly through the Google Drive cloud channel), the core exfiltration is confirmed through the physical media evidence. The twelve additional disguised files on RM2's FAT32 partition in directories suggesting "pricing" and "technical" content categories may represent additional exfiltrated workplace data beyond the five confirmed Secret Project documents, but file content analysis was not possible due to extraction limitations.

The presence of a resignation letter on the suspect's desktop, combined with the systematic pre-departure cleanup activity, indicates this was an end-of-employment data theft — a common insider threat pattern where the departing employee extracts proprietary data before separation. The timing of the CD-ROM burning (one day after the final cleanup) and the "security checkpoint cd-r" search query suggest the suspect intended to physically remove the optical media from the premises.

## Immediate Tactical Containment

1. Preserve and physically secure all four evidence items (PC disk image, RM1 USB, RM2 USB, RM3 CD-ROM) under chain of custody. Prevent any further access to the original media or their forensic images.

2. Disable the user account "informant" (iaman.informant@nist.gov, SID ending -1000) across all organizational identity systems, including Active Directory, email, VPN, and any cloud service SSO integrations.

3. Revoke access and initiate session termination for the Google Drive account associated with iaman.informant@nist.gov. Issue a preservation request to Google for the account's Drive contents, sync history, and access logs covering February 1 through March 31, 2015.

4. Revoke access to the iCloud account associated with the icloudsetup.exe installation discovered on informant-PC. Issue a preservation request to Apple for account activity during the same period.

5. Block USB serial numbers 4C530012450531101593 and 4C530012550531106501 (SanDisk Cruzer Fit devices) at the endpoint management level to prevent reconnection to any organizational system.

6. Quarantine the physical workstation associated with informant-PC and preserve the HL-DT-ST DVD+-RW GT80N optical drive or its VMware configuration for potential additional media recovery.

7. Search email systems for any messages sent from or to iaman.informant@nist.gov containing attachments matching the filenames [secret_project]_design_concept.ppt, [secret_project]_detailed_design.pptx, [secret_project]_revised_points.ppt, [secret_project]_detailed_proposal.docx, or [secret_project]_proposal.docx, or containing the strings "ireap," "umer," or "secret_project."

8. Notify the University of Maryland IREAP/UMER project stakeholders of the potential exposure of their proprietary research documents, including design concepts, detailed designs, and formal proposals.

## Strategic Remediation

**Removable Media Control Failure.** The suspect connected two personal SanDisk Cruzer Fit USB devices (S/N 4C530012450531101593 and 4C530012550531106501) to the workstation and copied 74 MB of proprietary data without generating any security alert. The RM1 device was even labeled "Authorized USB," suggesting that either no USB device whitelisting policy existed or the label was intended to circumvent visual inspection. Finding f_8c32da15 (USB device connections) and f_3f7b9464 (document exfiltration) demonstrate that endpoint Data Loss Prevention (DLP) controls were either absent or ineffective. Implementing USB device whitelisting restricted to organizationally-provisioned devices with registered serial numbers, combined with real-time monitoring of large file transfers to removable media, would have blocked the primary exfiltration vector.

**Optical Media Exfiltration Path.** The suspect's search for "security checkpoint cd-r" (finding f_bba83e45) reveals awareness that CD-ROM media could bypass physical security screening at facility exit points. The subsequent creation of RM3 one day after the PC cleanup (finding f_697d9034) confirms this vector was exploited. Physical security controls at facility boundaries should be reviewed to include inspection or prohibition of optical media, particularly for personnel with access to sensitive research data or those in the separation process.

**Cloud Storage Exfiltration Path.** Google Drive sync and iCloud setup were installed on the workstation (finding f_d7cd174b, ShimCache entries #171 and #172) without generating any security alert, creating potential cloud-based exfiltration channels. Finding f_f767bcd0 identifies this as a deliberate multi-vector strategy researched through "cloud storage" and "google drive" search queries. Cloud application controls — either through network-level blocking of personal cloud storage services or endpoint-level application whitelisting — would have prevented the installation and execution of unauthorized synchronization software on systems handling sensitive data.

**Anti-Forensics Tool Availability.** The suspect downloaded Eraser 6.2.0.2962 and CCleaner 5.04 from the internet (confirmed by Zone.Identifier ADS on deleted installers in finding f_04f56daf), installed them, and used them to destroy forensic artifacts including browser history, Jump Lists, LNK files, and Shellbags (finding f_ff5032dd). Application whitelisting or software restriction policies that prevent the installation and execution of unauthorized applications — particularly known anti-forensics and secure deletion tools — would have preserved the forensic artifacts that were successfully destroyed, and would have generated alertable installation events.

**Departing Employee Monitoring Gap.** The suspect had a resignation letter on their desktop (finding f_7dc3ab86) and conducted the entire exfiltration and cleanup campaign during an apparent separation period. The multi-week timeline from initial exfiltration (February 15) through final cleanup (March 25-26) provided ample operational window. Organizations handling sensitive research data should implement enhanced monitoring for users in the separation process, including elevated logging of file access patterns, removable media connections, and software installations. The USBSTOR registry entries and EVTX system logs that ultimately proved the USB connections existed but were not monitored in real-time.

**Browser History and Audit Log Preservation.** CCleaner's execution destroyed browser history databases that contained the suspect's research into data leakage methods and anti-forensics tools (finding f_bc4758c8). While bulk_extractor recovered search query fragments from unallocated space, the complete browsing timeline was lost. Centralized, tamper-resistant logging of web browsing activity to a SIEM or log aggregation platform — rather than relying solely on local browser databases — would have preserved this evidence regardless of local cleanup tool execution. Similarly, forwarding Windows Event Logs to a central collector would have preserved EVTX data even if the suspect had targeted event log clearing (which in this case they did not).

## Conclusion

**Q1. What systems were compromised?** One system was involved: the Windows 7 workstation "informant-PC" (WORKGROUP). This was not an external compromise but an insider abuse of authorized access. The user account "informant" (Iaman Informant, iaman.informant@nist.gov) operated entirely within its legitimate access scope, requiring no privilege escalation or exploitation of technical vulnerabilities.

**Q2. How did the attacker gain initial access?** The insider had authorized local access to the workstation through the "informant" user account (RID 1000, interactive logon Type 2). No external access vector, credential theft, or unauthorized authentication was required. Security EVTX logs confirm all logons were local — no network logons (Type 3/10) from external systems were detected.

**Q3. What lateral movement occurred?** No lateral movement occurred. Composite lateral movement analysis returned zero indicators. No network logon events, RDP sessions, WinRM activity, or SMB connections to other systems were detected. The suspect operated exclusively on the single workstation, consistent with a standalone machine in a WORKGROUP configuration.

**Q4. What persistence mechanisms were installed?** No malicious persistence mechanisms were installed. Composite persistence analysis identified 58 entries, all of which were standard Windows services and registry keys. The suspect's objective was data theft, not ongoing system access. The anti-forensics tools (Eraser, CCleaner) were installed temporarily for cleanup purposes and then deleted, rather than maintained for persistent access.

**Q5. Was data exfiltrated, and if so, what and how much?** Data exfiltration is confirmed across multiple vectors. Five proprietary IREAP/UMER research documents totaling approximately 74 MB were confirmed exfiltrated to USB media (RM1 and RM2) on February 15, 2015. The same or related document content was burned to CD-ROM (RM3) on March 26, 2015. Google Drive cloud sync was operational from February 19, 2015, representing a likely but unconfirmed third exfiltration channel — the deleted sync databases prevent confirmation of specific document uploads. An additional twelve files on RM2's FAT32 partition in "pricing" and "technical" themed directories may represent additional exfiltrated data, but file content could not be analyzed.

**Q6. What is the full timeline of the incident?** The incident spans from at least October 31, 2014 (earliest datable search history) through March 26, 2015 (CD-ROM creation). Key milestones include: research and planning (October 2014 – January 2015), initial USB exfiltration (February 15, 2015), Google Drive deployment (February 19, 2015), CCleaner first use (March 13, 2015), USB media review and initial cleanup (March 23, 2015), systematic USB file deletion (March 24, 2015), anti-forensics tool reinstallation on PC (March 25, 2015), and final CD-ROM exfiltration (March 26, 2015).

**Q7. What is the total scope and business impact?** The confirmed scope includes five proprietary research documents covering design concepts, detailed technical designs, revised specifications, and formal proposals for the IREAP/UMER project. These were replicated across at least four independent copies on three physical media devices and potentially uploaded to cloud storage, creating uncontrolled copies outside organizational custody. The anti-forensics campaign successfully destroyed local filesystem traces, browser history, and user activity artifacts, but failed to eliminate registry, ShimCache, Prefetch, and event log evidence. The investigation gaps — particularly the irrecoverable Google Drive sync databases and the twelve unanalyzed files on RM2 — mean the confirmed scope may understate the actual volume of exfiltrated data.

**Q8. What are the recommended remediation actions?** The primary remediation actions are: implement USB device whitelisting restricted to organizationally-provisioned devices; deploy DLP controls monitoring file transfers to removable media and cloud storage services; enforce application whitelisting to prevent installation of unauthorized software including anti-forensics tools; enhance monitoring of departing employees with elevated logging of file access, removable media, and software installations; review physical security controls for optical media at facility exit points; and implement centralized, tamper-resistant log forwarding to preserve forensic artifacts regardless of local cleanup activity.


---

## Overview

| | |
|---|---|
| Findings | **33** (29 confirmed, 4 inference) |
| Severity | 0 critical, 15 high, 7 medium, 0 low, 11 info |
| Sources | 33 evidence sources across 723 tool calls |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| cfreds_2015_data_leakage_pc.7z.001 | `7409b09714121f56be88f161450ebad92e194ff0554462be3187525eb76aa695` | 2.0 GB |
| cfreds_2015_data_leakage_pc.E01 | `e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9` | 2.0 GB |
| cfreds_2015_data_leakage_rm1.E01 | `a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121` | 74.6 MB |
| cfreds_2015_data_leakage_rm2.7z | `ade9fb60ba1f700b93c6b8b1f538c72000411e5b30037dc95c300c5a0aeafd65` | 219.2 MB |
| cfreds_2015_data_leakage_rm2.E01 | `25215f9bcb51ceee9147886ed3f5c13ef148de634fc5114491e0f8dad8b15696` | 243.2 MB |
| cfreds_2015_data_leakage_rm3_type1.7z | `f30f3408bf1a0eec5a34851c66a711634618430ac1794b24afa917b3b2c729e1` | 92.8 MB |
| cfreds_2015_data_leakage_rm3_type2.7z | `9e6137a9b101ef7ff7e12fcf8740a83a559179d0d3d75daedf4b1c40e98a8fef` | 78.7 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | `336e1307721ef5f63679379961d1716b74f986e69df8c40117d9cea7858d512b` | 90.2 MB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2003-09-24T15:33:42 | RM2 Personal Image Files with EXIF Metadata — Kodak Camera Photos from 2003-2013 | INFO | tsk.timeline, bulk.exif |
| 2014-10-31T15:05:00 | Premeditated Anti-Forensics Research: Search History Reveals Deliberate Planning of Data Leakage and Evidence Destruction | HIGH | bulk.url_searches, ez.shimcache, evtx.windows_system32_winevt_logs_application |
| 2014-12-04T11:24:50 | Document Metadata Contains University of Maryland (UMD) References | INFO | bulk.url, bulk.url_services, bulk.domain |
| 2014-12-16T12:10:26 | RM2 Contains Disguised Copies of Secret Project Documents with Falsified Extensions | HIGH | tsk.timeline, tsk.filelist, bulk.zip |
| 2015-01-12T22:56:36 | ShimCache Execution Timeline: Anti-Forensics Tools, Cloud Sync, and Software Installations | HIGH | ez.shimcache |
| 2015-02-15T16:51:38 | Proprietary "Secret Project" Documents Exfiltrated to Removable USB Media | HIGH | tsk.timeline, tsk.filelist, tsk.fsstat |
| 2015-02-15T16:51:38 | RM2 NTFS Partition Contains Secret Project Files with Original Filenames | HIGH | tsk.filelist, tsk.partitions, tsk.timeline |
| 2015-02-15T16:51:38 | Multi-Vector Exfiltration Strategy: USB, CD-ROM, and Cloud Storage Channels Used Sequentially | HIGH | tsk.timeline, tsk.filelist, ez.shimcache, ez.mft, evtx.windows_system32_winevt_logs_system, exiftool.metadata, bulk.url_searches, composite.execution, composite.exfil |
| 2015-02-19T18:24:24 | Google Drive Sync Binary Installed February 2015 — Pre-dates Known Exfiltration Timeline | MEDIUM | composite.execution, composite.exfil, registry.software, tsk.filelist |
| 2015-02-27T17:20:18 | Deleted Files on USB Indicate Directory Reorganization and Document Editing | MEDIUM | tsk.timeline, tsk.filelist |
| 2015-03-13T11:10:26 | Anti-Forensics Tools Downloaded, Installed, Executed, and Deleted on Host PC | HIGH | tsk.filelist |
| 2015-03-13T11:10:26 | CCleaner Effectively Destroyed Browser History, Jump Lists, LNK Files, and Shellbags — Forensic Artifact Gaps Across All User Activity Categories | HIGH | browser.history, ez.jumplists, ez.lnkfiles, ez.shellbags, tsk.filelist, ez.shimcache |
| 2015-03-22T14:33:54 | Suspect User "Iaman Informant" Identified with Resignation Letter on Desktop | HIGH | tsk.filelist |
| 2015-03-22T14:33:54 | User "informant" (Iaman Informant) Identified as Primary Account with NIST Email | MEDIUM | registry.sam, bulk.email, evtx.windows_system32_winevt_logs_security |
| 2015-03-23T14:32:20 | Coordinated Multi-Device Evidence Destruction Campaign: Synchronized Cleanup Across PC, RM1, and RM2 Over 3-Day Window | HIGH | evtx.windows_system32_winevt_logs_system, evtx.windows_system32_winevt_logs_application, bulk.url_searches, tsk.timeline, ez.shimcache, exiftool.metadata |
| 2015-03-23T14:32:20 | Unresolved Investigation Gaps: Key Artifacts Irrecoverable Due to Anti-Forensics and Extraction Limitations | MEDIUM | browser.history, ez.jumplists, ez.lnkfiles, ez.shellbags, tsk.filelist |
| 2015-03-23T16:55:17 | Systematic Deletion of All Files on RM2 — Anti-Forensics Evidence Destruction | HIGH | tsk.timeline, tsk.filelist |
| 2015-03-23T18:31:10 | Two SanDisk Cruzer Fit USB Devices Connected to Host PC on March 23–24, 2015 | HIGH | registry.system, ez.shimcache, tsk.filelist |
| 2015-03-23T18:31:10 | USB Device Serial Numbers Mapped to Connection Dates via EVTX System Log and Registry Cross-Correlation | HIGH | evtx.windows_system32_winevt_logs_system, registry.system, ez.shimcache |
| 2015-03-24T17:02:36 | RM2 Volume Label "IAMAN $_@" Directly Links Device to Suspect User | MEDIUM | tsk.filelist, tsk.timeline, bulk.email |
| 2015-03-25T14:47:40 | PC MFT Contains No Surviving Secret Project Document Traces — Anti-Forensics Cleanup Effective on Local Filesystem | MEDIUM | ez.mft, ez.shimcache, bulk.url_searches |
| 2015-03-26T18:35:29 | Cross-Media Correlation: Secret Project IREAP/UMER References Present on All Four Evidence Items | HIGH | bulk.domain, bulk.url, bulk.url_services |
| 2015-03-26T18:35:29 | CD-ROM Burning Research Corroborates RM3 as Planned Exfiltration Vector — Search-to-Action Chain Across PC and RM3 | HIGH | bulk.url_searches, exiftool.metadata, ez.mft |
| 2015-03-26T18:35:29 | RM3 Contains Government IT Governance DOCX Document from GovDocs Corpus | MEDIUM | bulk.domain, bulk.exif, bulk.rfc822, bulk.url_services |
| 2015-03-26T18:35:29 | RM3 Media Identification: CD-ROM with UDF Filesystem | INFO | exiftool.metadata |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Proprietary "Secret Project" Documents Exfiltrated to Removable USB Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-02-15T16:52:20 |
| **Sources** | tsk.timeline, tsk.filelist, tsk.fsstat |
| **Evidence Refs** | tc_8fc9c2ee, tc_4f4bb8a4, tc_ebd0cd12 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1005](https://attack.mitre.org/techniques/T1005/) |


The removable media device (RM1) labeled "Authorized USB" contains a folder structure "RM#1/Secret Project Data/" with 5 proprietary documents totaling approximately 74 MB:

**Design documents (under /design/):**
- [secret_project]_design_concept.ppt (1.8 MB, modified 2014-12-04 11:24:50)
- [secret_project]_detailed_design.pptx (16.4 MB, modified 2014-12-16 11:10:26)
- [secret_project]_revised_points.ppt (14.5 MB, modified 2015-01-23 15:47:10)

**Proposal documents (under /proposal/):**
- [secret_project]_detailed_proposal.docx (35.2 MB, modified 2014-12-18 16:50:58)
- [secret_project]_proposal.docx (6.5 MB, modified 2014-12-19 14:53:46)

The filesystem timeline reveals a **bulk copy operation on Sunday, February 15, 2015 between 16:51:38 and 16:52:20** (42 seconds), during which all 5 files and their directory structure were written to the USB device simultaneously. The access timestamps (.a) and birth timestamps (.b) cluster within this narrow window, consistent with a single-session copy from a source system.

The documents existed in the file system under two directory trees with identical inode numbers, indicating the exFAT filesystem referenced the same files from both "RM#1/Secret Project Data/" and "Secret Project Data/Secret Project Data/". The root-level "Secret Project Data" directory (inode 2054) is marked as deleted, suggesting the directory was renamed or reorganized after the initial copy.

The documents contain embedded references to http://www.ireap.umd.edu/umer and http://www.umer.umd.edu/ (University of Maryland Institute for Research in Electronics and Applied Physics), indicating the source of the proprietary documents.



### 2. [HIGH] Anti-Forensics Tools Downloaded, Installed, Executed, and Deleted on Host PC

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-13T11:10:26 to 2015-03-25T14:50:15 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_193ef23c, tc_f0d1b4f2, tc_edcee5e2 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/) |


The host PC (cfreds_2015_data_leakage_pc.E01) shows evidence that user "informant" (username: informant, full name: "Iaman Informant" per resignation letter) downloaded, installed, and subsequently deleted two anti-forensics/cleanup tools:

**Eraser 6.2.0.2962 (Secure Deletion Tool):**
- Installer: Users/informant/Desktop/Download/Eraser 6.2.0.2962.exe — DELETED (-/r * 75101-128-4)
- Zone.Identifier ADS: DELETED (-/r * 75101-128-5), confirming internet download
- Desktop shortcut: Users/Public/Desktop/Eraser.lnk — DELETED (-/r * 75235-128-3)
- Prefetch evidence of BOTH installer AND application execution:
  - Windows/Prefetch/ERASER 6.2.0.2962.EXE-BE552234.pf (r/r 75473-128-4) — installer was run
  - Windows/Prefetch/ERASER.EXE-CE61944A.pf (r/r 23135-128-4) — application was executed

**CCleaner 5.04 (System Cleaner):**
- Installer: Users/informant/Desktop/Download/ccsetup504.exe — DELETED (-/r * 75186-128-4)
- Zone.Identifier ADS: DELETED (-/r * 75186-128-5), confirming internet download
- Installation directory: Program Files/CCleaner/ — ENTIRE DIRECTORY DELETED (-/d * 75246-144-1)
  - CCleaner.exe — DELETED
  - CCleaner64.exe — DELETED
  - uninst.exe — DELETED
  - All ~50 language DLLs — DELETED
- Desktop shortcut: Users/Public/Desktop/CCleaner.lnk — DELETED (-/r * 75306-128-3)
- Prefetch evidence of BOTH installer AND application execution:
  - Windows/Prefetch/CCSETUP504.EXE-6BA2F6A1.pf (r/r 75242-128-4) — installer was run
  - Windows/Prefetch/CCLEANER64.EXE-779BD542.pf (r/r 75309-128-4) — application was executed

The pattern is consistent: both tools were downloaded from the internet, installed, executed (evidenced by Prefetch), and then the installers, program files, and shortcuts were all deleted. However, the Prefetch files for both tools survived the cleanup, proving execution. This is a clear anti-forensics pattern where the subject attempted to destroy evidence of having used secure deletion and system cleaning tools.



### 3. [HIGH] Suspect User "Iaman Informant" Identified with Resignation Letter on Desktop

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:01 |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_193ef23c, tc_f0d1b4f2 |
| **ATT&CK** | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |


The host PC has a user account named "informant" (SID ending in -1000, based on Prefetch AgGlUAD filename) whose Desktop contains a resignation letter, linking this user directly to the data leakage:

- **Resignation_Letter_(Iaman_Informant).docx** (inode 23554-128-3) — Microsoft Word document
- **Resignation_Letter_(Iaman_Informant).xps** (inode 72008-128-4) — XPS version of the same letter (created using XPS printer driver, XPSRCHVW.EXE-FEB3BF01.pf prefetch exists)
- **~$signation_Letter_(Iaman_Informant).docx** — DELETED temp/lock file (r/- * 0), indicating the document was previously open in Word

The full name "Iaman Informant" embedded in the filename identifies the suspected insider. The user's Desktop also contains:
- A "Download" folder with IE11 installer (present) and the deleted Eraser/CCleaner installers
- A deleted Google Drive.lnk shortcut (-/r * 75066-128-4)
- A deleted directory "[QAT" (-/d * 74402-144-7)

Additionally, the user profile contains:
- Google Drive sync folder (Users/informant/Google Drive/) with a deleted "happy_holiday.jpg"
- Google Drive sync application installed and executed (GOOGLEDRIVESYNC.EXE prefetch exists)
- iCloud setup downloaded (Users/informant/Downloads/icloudsetup.exe)
- Microsoft Word executed (WINWORD.EXE-CECBA770.pf prefetch exists)
- Outlook executed (OUTLOOK.EXE-1DF422BF.pf prefetch exists)

The combination of a resignation letter, anti-forensics tool usage, cloud sync installation, and the secret project data on the USB device strongly indicates this user was the insider responsible for the data exfiltration.



### 4. [HIGH] Two SanDisk Cruzer Fit USB Devices Connected to Host PC on March 23–24, 2015

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:31:10 to 2015-03-24T13:58:33 |
| **Sources** | registry.system, ez.shimcache, tsk.filelist |
| **Evidence Refs** | tc_de49d659, tc_e4edb6e3, tc_105f4637 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1005](https://attack.mitre.org/techniques/T1005/) |


The host PC's USBSTOR registry key documents two SanDisk Cruzer Fit USB devices (Rev 2.01) that were connected to the system:

**USB Device 1 — S/N: 4C530012450531101593&0**
- USBSTOR key LastWrite: 2015-03-24 13:38:00Z
- Device Parameters LastWrite: 2015-03-23 18:31:11Z
- LogConf LastWrite: 2015-03-23 18:31:10Z
- Properties LastWrite: 2015-03-23 18:31:11Z
- FriendlyName: "SanDisk Cruzer Fit USB Device"

**USB Device 2 — S/N: 4C530012550531106501&0**
- USBSTOR key LastWrite: 2015-03-24 13:58:33Z
- Device Parameters LastWrite: 2015-03-24 13:58:33Z
- LogConf LastWrite: 2015-03-24 13:58:32Z
- Properties LastWrite: 2015-03-24 13:58:33Z
- FriendlyName: "SanDisk Cruzer Fit USB Device"

Both serial numbers begin with "4C5300124" and "4C5300125", suggesting same-brand devices. The DeviceClasses registry key confirms the first device was associated with a volume at 2015-03-24 13:38:00Z.

Additionally, ShimCache entry #152 shows `D:\IE11-Windows6.1-x64-en-us.exe` was accessed from drive D:, and entry #281 shows `D:\proplusr.ww\ose.exe` (Office installer), confirming files were executed directly from the USB device mapped as drive D:.

The USB media image (RM1, "Authorized USB") contains the exfiltrated Secret Project documents. The USB device parameters activity on March 23, 2015, aligns with the USB filesystem timeline showing the Word temp file `~$ecret_project]_proposal.docx` was created at 2015-03-23 14:37:52 — confirming the USB was connected to this PC and documents were accessed.



### 5. [HIGH] ShimCache Execution Timeline: Anti-Forensics Tools, Cloud Sync, and Software Installations

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-01-12T22:56:36 to 2015-03-25T14:50:15 |
| **Sources** | ez.shimcache |
| **Evidence Refs** | tc_9f658671, tc_8ab42c01, tc_9af4a336 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


The ShimCache (AppCompatCache) from the SYSTEM registry hive provides precise execution timestamps for key applications relevant to the data leakage investigation. These timestamps establish a chronological timeline of the suspect's activity:

**Anti-Forensics Tools:**
- **Eraser.exe** (Entry #19): LastModified 2015-01-12 22:56:36 — Executed=Yes. The secure deletion tool binary dates to January 2015.
- **CCleaner64.exe** (Entry #61): LastModified 2015-03-13 11:10:26 — Executed=Yes. First CCleaner activity in March.
- **CCleaner uninst.exe** (Entry #51): LastModified 2015-03-13 13:55:38 — Executed=Yes. Uninstaller ran same day.
- **ccsetup504.exe** (Entry #83): LastModified 2015-03-25 14:48:28 — Executed=Yes. CCleaner re-downloaded on the last day.
- **Eraser 6.2.0.2962.exe** (Entry #118): LastModified 2015-03-25 14:47:40 — Executed=Yes. Eraser installer run on final day.
- **eraserInstallBootstrapper** (Entry #117): LastModified 2015-03-25 14:50:15 — Executed=Yes. .NET bootstrapper for Eraser install.

**Cloud Sync Applications:**
- **googledrivesync.exe** (Entry #172): LastModified 2015-03-23 19:56:33 — Executed=Yes. Google Drive sync downloaded.
- **icloudsetup.exe** (Entry #171): LastModified 2015-03-23 19:56:53 — Executed=Yes. iCloud setup downloaded within 20 seconds of Google Drive.

**USB Drive Activity:**
- **D:\IE11-Windows6.1-x64-en-us.exe** (Entry #152): 2015-03-22 15:11:04 — Executed from USB drive D:.
- **D:\SETUP.EXE** (Entry #275): 2012-10-02 00:25:32 — Office setup from USB drive D:.
- **D:\proplusr.ww\ose.exe** (Entry #281): 2012-10-01 03:41:43 — Office installer from USB.

**Key Timeline:**
1. Jan 12, 2015: Eraser binary exists on system
2. Feb 15, 2015: Secret project documents bulk-copied to USB (from tsk.timeline)
3. Mar 13, 2015: CCleaner first executed and uninstalled
4. Mar 22, 2015: IE11 installed from USB drive D:
5. Mar 23, 2015: Google Drive sync + iCloud setup downloaded; USB documents edited
6. Mar 25, 14:47-14:50: Eraser and CCleaner reinstalled in rapid succession — final cleanup



### 6. [HIGH] RM2 Contains Disguised Copies of Secret Project Documents with Falsified Extensions

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-16T12:10:26 to 2015-01-23T16:47:10 |
| **Sources** | tsk.timeline, tsk.filelist, bulk.zip |
| **Evidence Refs** | tc_defdcda0, tc_5c41657d, tc_8b1e5576, tc_fc9ab593 |
| **ATT&CK** | [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1027](https://attack.mitre.org/techniques/T1027/) |


The FAT32 partition of RM2 (cfreds_2015_data_leakage_rm2.E01) contains four deleted files with innocuous filenames and false extensions that match EXACTLY in file size to the four largest Secret Project documents found on RM1:\n\n**File Size Matching (RM2 disguised → RM1 original):**\n| RM2 (FAT32, disguised) | Size | RM1 (original) | Size |\n|---|---|---|---|\n| proposal/a_gift_from_you.gif | 35,226,880 | [secret_project]_detailed_proposal.docx | 35,226,880 |\n| design/winter_whether_advisory.zip | 16,381,123 | [secret_project]_detailed_design.pptx | 16,381,123 |\n| design/winter_storm.amr | 14,547,968 | [secret_project]_revised_points.ppt | 14,547,968 |\n| proposal/landscape.png | 6,484,502 | [secret_project]_proposal.docx | 6,484,502 |\n\n**Confirmation via OOXML structures:** Bulk extractor ZIP analysis of RM2 carved Office XML internal structures including `word/document.xml`, `word/numbering.xml`, `ppt/presentation.xml`, `ppt/slides/`, and `docProps/core.xml`. These internal ZIP entries are characteristic of OOXML Office documents (.docx/.pptx), confirming the disguised files contain Office document content despite having .gif, .zip, .amr, and .png extensions.\n\n**Timestamp correlation:** The modification timestamps on RM2's FAT32 partition are consistently 1 hour later than the NTFS timestamps for the same documents, consistent with FAT32 storing local time vs NTFS storing UTC in a UTC+1 timezone.\n\n**Additional Disguised Files (12 more, unconfirmed content):**\nBeyond the four confirmed Secret Project copies, RM2 contained 12 additional deleted files in themed directories:\n- PRICIN~1/ (pricing?): my_favorite_cars.db (1.2MB), my_favorite_movies.7z (100KB), new_years_day.jpg (10.2MB), super_bowl.avi (10.3MB)\n- progress/: my_friends.svg (58KB), my_smartphone.png (4.4MB), new_year_calendar.one (27KB)\n- TECHNI~1/ (technical?): diary_#1d.txt through diary_#3p.txt (6 files, 121KB–2.3MB)\n\nThe directory short names PRICIN~1 and TECHNI~1 suggest long filenames containing \"pricing\" and \"technical\" — consistent with workplace data categories. File header analysis was not possible (extract_file_by_inode failed for all 12 files), but the naming pattern mirrors the disguise strategy of the confirmed documents.\n\n**Anti-forensics intent:** The deliberate renaming of files with innocent names (winter_storm, a_gift_from_you, landscape) and false extensions (.amr, .gif, .png, .zip) demonstrates intentional concealment. All files were deleted during the Mar 23-24 2015 cleanup.



### 7. [HIGH] Systematic Deletion of All Files on RM2 — Anti-Forensics Evidence Destruction

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T16:55:17 to 2015-03-24T17:02:36 |
| **Sources** | tsk.timeline, tsk.filelist |
| **Evidence Refs** | tc_defdcda0, tc_5c41657d |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/) |


Every file on RM2 has been deleted across both partitions, constituting systematic evidence destruction. The MAC timeline reveals a precise two-day deletion sequence:

**FAT32 Partition Deletion Timeline:**

Phase 1 — Mon Mar 23 2015 16:55:17-16:55:37: All 22 personal image files deleted (amalfi.bmp through wat.gif). Birth timestamps clustered within 20 seconds indicate batch deletion.

Phase 2 — Tue Mar 24 2015 09:54:54-10:00:18: All organized folders and their contents deleted:
- 09:54:54: progress/ directory modified
- 09:55:18: proposal/ directory modified
- 09:56:22: TECHNI~1/ directory modified
- 09:57:14: design/ directory modified
- 09:57:32: PRICIN~1/ directory modified
- 09:59:26-10:00:18: All files within directories received birth timestamps (deletion metadata update)

Phase 3 — Tue Mar 24 2015 15:51:47-15:51:48: desktop.ini deleted (the last regular file)

Phase 4 — Tue Mar 24 2015 17:02:36: Volume label "IAMAN $_@" modified (final timestamp on device)

**NTFS Partition Deletion Timeline:**

- Feb 27 2015 17:20:18: "Secret Project Data" root directory modified (possibly initial reorganization)
- Mar 23 2015 14:32:20-14:32:21: "Secret Project Data (deleted)" directory accessed/born (deletion)
- Mar 23 2015 14:37:52-14:37:54: Word temp file ~$ecret_project]_proposal.docx created then deleted (document was opened)
- Mar 23 2015 14:38:21-14:38:46: OrphanFile-5138 deleted-realloc

**Total deleted content:** 5 directories, 4 disguised secret project documents, 6 diary files, 4 files in PRICIN~1/, 3 files in progress/, 22 personal images, 1 desktop.ini = ~40 files, all marked as deleted (*) or orphaned.

The systematic, phased deletion across two days correlates with the host PC's ShimCache evidence showing Eraser and CCleaner anti-forensics tools reinstalled on Mar 25 2015 and USBSTOR showing both USB devices connected on Mar 24 2015. This is coordinated evidence destruction.



### 8. [HIGH] RM2 NTFS Partition Contains Secret Project Files with Original Filenames

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-23T14:38:46 |
| **Sources** | tsk.filelist, tsk.partitions, tsk.timeline |
| **Evidence Refs** | tc_0ab3e0f9, tc_5c41657d, tc_defdcda0 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The NTFS partition on RM2 (second partition, detected via tsk.filelist.p2 and tsk.timeline) contains the same Secret Project documents found on RM1, with their ORIGINAL filenames intact — unlike the FAT32 partition where they were disguised. This reveals RM2 held the exfiltrated data in two forms simultaneously.

**Files found on RM2 NTFS partition (all under /RM#1/Secret Project Data/ and /Secret Project Data/Secret Project Data/):**
- design/[secret_project]_design_concept.ppt (1,810,432 bytes) — Modified: Thu Dec 04 2014 11:24:50
- design/[secret_project]_detailed_design.pptx (16,381,123 bytes) — Modified: Tue Dec 16 2014 11:10:26
- design/[secret_project]_revised_points.ppt (14,547,968 bytes) — Modified: Fri Jan 23 2015 15:47:10
- proposal/[secret_project]_detailed_proposal.docx (35,226,880 bytes) — Modified: Thu Dec 18 2014 16:50:58
- proposal/[secret_project]_proposal.docx (6,484,502 bytes) — Modified: Fri Dec 19 2014 14:53:46

**Copy operation timestamp:** Sun Feb 15 2015 16:51:38-16:52:20 — All directory and file access/birth timestamps cluster in this 42-second window, identical to the RM1 copy timeline. This means the data was copied to BOTH RM1 and RM2's NTFS partition in the same session on Feb 15, 2015.

**Dual path structure:** Files appear under both "/RM#1/Secret Project Data/" and "/Secret Project Data/Secret Project Data/" with identical inodes, indicating directory reorganization (the root "Secret Project Data" directory was deleted on Feb 27, 2015).

**Word temp file evidence:** On Mar 23, 2015 14:37:52, a ~$ecret_project]_proposal.docx temp file was created (162 bytes), proving the document was opened in Microsoft Word on that date directly from RM2. This temp file was subsequently deleted.

The NTFS partition thus serves as a third confirmation (alongside RM1 and the FAT32 partition) that the Secret Project documents were exfiltrated to removable media.

**Affected Systems:** tsk.filelist, tsk.partitions, tsk.timeline



### 9. [HIGH] Cross-Media Correlation: Secret Project IREAP/UMER References Present on All Four Evidence Items

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-26T18:35:29 |
| **Sources** | bulk.domain, bulk.url, bulk.url_services |
| **Evidence Refs** | tc_0beeb91a, tc_7639c29f, tc_849cc719 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


The IREAP/UMER URL references that characterize the "Secret Project" documents appear on all four evidence items in the case, establishing a data provenance chain:

**RM3 Evidence** (bulk.domain, source_id 61):
- Offset 10905291: www.ireap.umd.edu — "Website: http://www.ireap.umd.edu/umer"
- Offset 10905335: www.umer.umd.edu — "cations: http://www.umer.umd.edu/"

**Cross-media matches** (ireap search across all sources):
- **RM1** (bulk.domain source_id 3, bulk.url source_id 4): IREAP/UMER references present
- **RM2** (bulk.domain source_id 51, bulk.url source_id 56): IREAP/UMER references present
- **PC** (bulk.domain source_id 12, bulk.url source_id 19): IREAP/UMER references present
- **RM3** (bulk.domain source_id 61): IREAP/UMER references present

**Additional cross-media indicators**:
- digitalcorpora.org/corpora/govdocs references appear on ALL four evidence items (RM1, RM2, PC, RM3)
- Kodak DC260 camera photos appear on both RM2 (photos from this camera model) and RM3 (EXIF records at offsets 1310146 and 9203260)
- whitehouse.gov/omb URLs (FEA Reference Model, OMB circulars) appear on both PC (bulk.url source_id 19) and RM3 (bulk.domain source_id 61)
- desert-estates.info references appear on RM3 (offset 53510926 and 53510955) and potentially on other media

The presence of IREAP/UMER references on the RM3 CD-ROM, combined with GovDocs corpus markers, indicates that the Secret Project document content (or a GovDocs document containing the same IREAP/UMER data) was also transferred to optical media. Combined with the post-cleanup burning date (March 26), this suggests RM3 may represent an additional data exfiltration vector.



### 10. [HIGH] Premeditated Anti-Forensics Research: Search History Reveals Deliberate Planning of Data Leakage and Evidence Destruction

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-10-31T15:05:00 to 2015-03-25T14:57:27 |
| **Sources** | bulk.url_searches, ez.shimcache, evtx.windows_system32_winevt_logs_application |
| **Evidence Refs** | tc_70f535eb, tc_9f658671, tc_4d759c80 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1518](https://attack.mitre.org/techniques/T1518/) |


Cross-correlation of bulk_extractor URL search history (bulk.url_searches) with ShimCache execution evidence, MFT file system artifacts, and removable media analysis reveals a deliberate, researched plan for data exfiltration and anti-forensics. The suspect's search queries, corroborated by subsequent tool execution across multiple evidence sources, demonstrate premeditation rather than opportunistic data theft.

**Phase 1 — Leakage Research (pre-exfiltration):**
- "information leakage cases" (n=47) — researching how others leaked data
- "how to leak a secret" (n=6) — explicit intent query
- "leaking confidential information" (n=2)
- "intellectual property theft" (n=6) — understanding the offense
- "data leakage methods" (n=1) — studying techniques

**Phase 2 — Exfiltration Channel Research:**
- "file sharing and tethering" (n=491) — most searched term, investigating transfer methods
- "cloud storage" (n=6+) — investigating cloud exfiltration
- "google drive" (n=10) — specific cloud service researched → **CORROBORATED**: Google Drive sync installed and executed (ShimCache entry #172, 2015-03-23 19:56:33)
- "apple icloud" (n=1) — alternative cloud channel → **CORROBORATED**: icloudsetup.exe downloaded (ShimCache entry #171, 2015-03-23 19:56:53)
- "cd burning method" (n=64) and "cd burning method in windows" (n=53) — optical media exfiltration research → **CORROBORATED**: RM3 CD-ROM burned 2015-03-26
- "security checkpoint cd-r" (n=1) — researching whether CD-Rs can pass physical security

**Phase 3 — Anti-Forensics Research:**
- "anti-forensic tools" (n=85) — explicit research
- "anti-forensics" (n=1+) — continued research
- "digital forensics" (n=1+) — understanding investigative methods
- "forensicswiki.org" visits (45 URL matches) — studying forensic methodology
- "nij.gov/topics/forensics/evidence/digital/" — NIJ Digital Evidence portal
- "what is windows system artifacts" (n=79) — understanding what forensics examines
- "windows event logs" (n=61) — studying what logs track
- "external device and forensics" (n=65) — USB forensics research
- "DLP DRM" (n=90) — data loss prevention awareness

**Phase 4 — Cleanup Tool Research & Execution:**
- "ccleaner" (n=65) → **CORROBORATED**: CCleaner64.exe executed (ShimCache, MFT: installed 2015-03-13, reinstalled 2015-03-25)
- "eraser" (n=51) → **CORROBORATED**: Eraser.exe executed (ShimCache, EVTX Application log: System Restore point "Installed Eraser 6.2.0.2962" at 2015-03-25 14:57:27)
- "system cleaner" (n=5+) — generic cleanup research
- "how to delete data" (n=5+) — deletion method research

**Phase 5 — Counter-Investigation Research:**
- "data recovery tools" (n=3+) — testing if deleted data can be recovered
- "how to recover data" (n=2+) — understanding recovery capabilities
- "investigation on windows machine" (n=64) — understanding forensic examination procedures
- "e-mail investigation" (n=88) — understanding email forensics
- "Forensic Email Investigation" (n=78) — same topic, refined search
- "outlook 2013 settings" (n=1) — potentially configuring/sanitizing email

The progression from leakage research → channel selection → anti-forensics study → tool deployment → counter-investigation awareness demonstrates a sophisticated, premeditated insider threat operation. Each research topic maps directly to actions taken across the evidence.



### 11. [HIGH] USB Device Serial Numbers Mapped to Connection Dates via EVTX System Log and Registry Cross-Correlation

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:31:10 to 2015-03-24T13:58:33 |
| **Sources** | evtx.windows_system32_winevt_logs_system, registry.system, ez.shimcache |
| **Evidence Refs** | tc_983ea682, tc_4f48ebaa, tc_7a9ccc13 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1005](https://attack.mitre.org/techniques/T1005/) |


Cross-correlation of three independent evidence sources — System EVTX event log, USBSTOR registry keys, and ShimCache — definitively maps the two SanDisk Cruzer Fit USB serial numbers to specific connection dates on the host PC (informant-PC):

**USB Device 1 — S/N: 4C530012450531101593:**
- EVTX System Log: USBSTOR driver service installation event at **2015-03-23 18:31:10Z** with DeviceInstanceID: USB\VID_0781&PID_5571\4C530012450531101593
- Registry USBSTOR: Device Parameters LastWrite **2015-03-23 18:31:11Z** (1 second after EVTX event)
- Registry USBSTOR: Main key LastWrite **2015-03-24 13:38:00Z** (second connection next day)
- Registry DeviceClasses: Volume association at **2015-03-24 13:38:00Z**

**USB Device 2 — S/N: 4C530012550531106501:**
- EVTX System Log: USBSTOR driver service installation event at **2015-03-24 13:58:32Z** with DeviceInstanceID: USB\VID_0781&PID_5571\4C530012550531106501
- Registry USBSTOR: All LastWrite timestamps cluster at **2015-03-24 13:58:32-33Z**

**Timeline Reconstruction:**
1. March 23, 18:31: Device 1 (S/N ...1593) first connected — Word temp file ~$ecret_project]_proposal.docx created at 14:37:52 on RM1/RM2 NTFS partition, confirming USB was connected earlier that day
2. March 24, 13:38: Device 1 reconnected
3. March 24, 13:58: Device 2 (S/N ...6501) first connected — 20 minutes after Device 1 reconnection

**COUNTER-ANALYSIS — Device-to-Media Mapping Limitation:**
The mapping of Device 1 → RM1 and Device 2 → RM2 is based on **temporal correlation only**. No definitive physical link (volume serial number in MountedDevices, volume label in registry, or drive letter assignment log) was found to directly match USB serial numbers to the specific RM1/RM2 media images. The RM1 volume serial number (5c75-4d3e, "Authorized USB") was NOT found in the registry MountedDevices key. The RM2 volume label ("IAMAN $_@") was NOT found in registry. While temporal correlation is strong — Device 1 connected on the same day files were accessed on RM1/RM2 NTFS, and Device 2 connected on the same day RM2 FAT32 files were deleted — the mapping remains circumstantial rather than definitive. Both devices are confirmed SanDisk Cruzer Fit USB drives with similar serial numbers ("4C5300124" vs "4C5300125"), indicating same product line.



### 12. [HIGH] CD-ROM Burning Research Corroborates RM3 as Planned Exfiltration Vector — Search-to-Action Chain Across PC and RM3

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-26T18:35:29 to 2015-03-26T18:35:29 |
| **Sources** | bulk.url_searches, exiftool.metadata, ez.mft |
| **Evidence Refs** | tc_70f535eb, tc_c007c848, tc_03f0b709 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Cross-system correlation between the PC's browser search history and the RM3 CD-ROM evidence establishes that the CD-ROM burning was a deliberately researched and planned exfiltration method, not an incidental copy.

**Search Query Evidence (PC, bulk.url_searches):**
- "cd burning method" — searched 64 times (including Bing auto-suggest queries)
- "cd burning method in windows" — searched 53 times (refining the search to Windows-specific methods)
- "security checkpoint cd-r" — searched 1 time, indicating concern about whether CD-Rs could pass physical security screening at workplace checkpoints

**CD-ROM Evidence (RM3):**
- Device: HL-DT-ST DVD+-RW GT80N optical drive (present in informant-PC)
- ISO creation: **2015-03-26 18:35:29 UTC** — one day AFTER the final cleanup on the PC (2015-03-25)
- Content: Government IT governance DOCX with IREAP/UMER references matching Secret Project documents
- Media: UDF v5.13 filesystem, single session, ~107.5 MB

**COUNTER-ANALYSIS — No Execution Evidence for CD Burning on informant-PC:**
Windows built-in isoburn.exe exists at Windows\winsxs\amd64_microsoft-windows-isoburn_... (created 2010-11-21 during OS installation). However, **isoburn.exe has NO ShimCache entry and NO Prefetch file**, meaning there is no direct execution evidence that the CD was burned on this specific machine. No third-party CD burning software appears in ShimCache either. The CD could have been burned on a different computer. Nevertheless, the content overlap (IREAP/UMER references matching documents only found on informant's USB devices), the search history on informant-PC for CD burning methods, and the post-cleanup timing (one day after Eraser/CCleaner reinstallation) still strongly associate RM3 with the suspect. The HL-DT-ST GT80N is a VMware virtual optical drive consistent with informant-PC's VMware environment.

**Timeline Coherence:**
1. Research: Suspect searched "cd burning method" and "cd burning method in windows" (date unknown but within browsing session)
2. Security concern: Searched "security checkpoint cd-r" — assessing whether optical media bypasses physical security
3. Evidence cleanup: 2015-03-24/25 — USB files deleted, CCleaner and Eraser deployed on PC
4. CD burned: **2015-03-26** — AFTER cleanup, creating a "clean" copy of the data on tamper-proof read-only media



### 13. [HIGH] Coordinated Multi-Device Evidence Destruction Campaign: Synchronized Cleanup Across PC, RM1, and RM2 Over 3-Day Window

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T14:32:20 to 2015-03-26T18:35:29 |
| **Sources** | evtx.windows_system32_winevt_logs_system, evtx.windows_system32_winevt_logs_application, bulk.url_searches, tsk.timeline, ez.shimcache, exiftool.metadata |
| **Evidence Refs** | tc_4f48ebaa, tc_4d759c80, tc_70f535eb, tc_defdcda0, tc_9f658671, tc_c007c848 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Cross-system temporal correlation reveals a coordinated evidence destruction campaign spanning the host PC and both USB devices over March 23-25, 2015. Each evidence source independently records cleanup activity that forms a coherent operational timeline when correlated.

**Day 1 — March 23, 2015: USB Access and Initial Cleanup**
- 14:32:20-14:32:21: RM2 NTFS "Secret Project Data" directory accessed/deleted
- 14:37:52-14:37:54: Word temp file ~$ecret_project]_proposal.docx created and deleted on RM1/RM2 NTFS (document opened for review)
- 16:55:17-16:55:37: RM2 FAT32 — All 22 personal image files batch-deleted (20 seconds)
- 18:31:10-11: PC EVTX System — USB device S/N 4C530012450531101593 USBSTOR driver installed
- 19:56:33: PC ShimCache — Google Drive sync downloaded
- 19:56:53: PC ShimCache — iCloud setup downloaded (20 seconds after Google Drive)

**Day 2 — March 24, 2015: Systematic USB Deletion and Second Device**
- 09:54:54-10:00:18: RM2 FAT32 — All organized directories and files deleted in sequence
- 13:38:00: USB device 1 reconnected (registry LastWrite)
- 13:58:32-33: PC EVTX System — USB device 2 first connection
- 15:51:47-48: RM2 FAT32 — desktop.ini deleted (last regular file)
- 17:02:36: RM2 FAT32 — Volume label "IAMAN $_@" modified (final timestamp on entire device)

**Day 3 — March 25, 2015: PC Cleanup Tool Reinstallation**
- 14:47:40: PC ShimCache — Eraser installer executed
- 14:48:28: PC ShimCache — CCleaner installer executed (48 seconds after Eraser)
- 14:50:15: PC ShimCache — Eraser bootstrapper executed
- 14:57:27: PC EVTX Application — System Restore point "Installed Eraser 6.2.0.2962" created

**Post-Cleanup — March 26, 2015:**
- 18:35:29: RM3 — CD-ROM burned (ISO creation timestamp)

**Cross-System Convergence (6 independent sources):** RM1/RM2 filesystem timelines, PC EVTX System/Application logs, PC Registry, PC ShimCache, RM3 ExifTool metadata. The phased destruction represents a methodical evidence destruction operation that was itself researched in advance.



### 14. [HIGH] CCleaner Effectively Destroyed Browser History, Jump Lists, LNK Files, and Shellbags — Forensic Artifact Gaps Across All User Activity Categories

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-13T11:10:26 to 2015-03-25T15:31:01 |
| **Sources** | browser.history, ez.jumplists, ez.lnkfiles, ez.shellbags, tsk.filelist, ez.shimcache |
| **Evidence Refs** | tc_146a400d, tc_5762cf5d, tc_5eef27d2, tc_a734971f, tc_b5f93af7 |
| **ATT&CK** | [T1070](https://attack.mitre.org/techniques/T1070/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Cross-system analysis of the PC's forensic artifact preservation reveals a systematic pattern: all user activity artifacts that would normally record file access patterns, document opens, and folder navigation returned zero results from parsing tools, despite the underlying database files existing on the filesystem.

**Empty Artifact Sources (all returned 0 windows after successful tool execution):**
1. **Browser History** (browser.history): SQLite databases located and queried but returned zero browsing records. This is consistent with CCleaner's browser history cleaning module targeting Internet Explorer and Chrome history databases.
2. **Jump Lists** (ez.jumplists): AutomaticDestinations-ms files exist on disk at `Users/informant/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/` (multiple files confirmed in tsk.filelist, including 47bb2136fda3f1ed and 4cc9bcff1a772a63.automaticDestinations-ms), but JLECmd extracted zero entries.
3. **LNK Files** (ez.lnkfiles): LECmd extracted zero shortcut records despite LNK files existing on disk (e.g., Google Drive.lnk at inode 75065-128-4, Desktop.lnk, Downloads.lnk).
4. **Shellbags** (ez.shellbags): SBECmd extracted zero folder navigation records from the user's UsrClass.dat.

**Impact on Investigation Questions:**
- Q10: Cannot timestamp the anti-forensics web searches (browser history wiped)
- Q11: Cannot confirm whether Shellbags/Jump Lists recorded the user navigating Secret Project paths on the PC or USB
- Q12: Cannot determine whether LNK files contained USB volume serial numbers matching RM1 (5c75-4d3e) or RM2 device IDs

**Artifacts That Survived CCleaner:**
In contrast, the following artifacts survived the cleanup and provided the investigation's primary evidence:
- Prefetch files (CCleaner's default settings do not clean Prefetch)
- Registry hives (USBSTOR, ShimCache, SAM — CCleaner targets specific registry keys but not ShimCache/USBSTOR)
- EVTX event logs (CCleaner's registry cleaner does not target event logs by default)
- MFT entries (file metadata survived even though files were deleted)
- Bulk_extractor carved content (browser cache/cookies in unallocated space)

**Assessment:**
The combination of CCleaner execution (confirmed by ShimCache entry #61: 2015-03-13, entry #83: 2015-03-25) and the systematic absence of all four user activity artifact categories constitutes confirmed evidence of artifact destruction. CCleaner's "Windows Explorer — Recent Documents" and "Internet Explorer — History" cleaning options, when executed, remove exactly the artifact types found to be empty.



### 15. [HIGH] Multi-Vector Exfiltration Strategy: USB, CD-ROM, and Cloud Storage Channels Used Sequentially

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-26T18:35:29 |
| **Sources** | tsk.timeline, tsk.filelist, ez.shimcache, ez.mft, evtx.windows_system32_winevt_logs_system, exiftool.metadata, bulk.url_searches, composite.execution, composite.exfil |
| **Evidence Refs** | tc_146a400d, tc_92aec3ca, tc_c007c848, tc_70f535eb, tc_defdcda0, tc_9f658671 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1005](https://attack.mitre.org/techniques/T1005/) |


Cross-system correlation across all four evidence items reveals a deliberate multi-vector exfiltration strategy where the suspect used three distinct data transfer channels in sequence, each researched beforehand:

**Vector 1 — USB Flash Drives (RM1 + RM2): February 15, 2015 [CONFIRMED]**
- Secret Project documents bulk-copied to exFAT USB device (RM1, volume serial 5c75-4d3e, label "Authorized USB") in a 42-second window (16:51:38-16:52:20)
- Same documents simultaneously copied to RM2's NTFS partition with original filenames
- RM2 FAT32 partition received disguised copies with falsified extensions (.gif, .zip, .amr, .png) and innocent filenames
- Evidence: tsk.timeline (RM1, RM2), tsk.filelist (RM1, RM2), bulk.zip (RM2 OOXML structures)
- Corroborated by: exact byte-for-byte file size matching across media, OOXML internal structures in falsely-extensioned files

**Vector 2 — Google Drive Cloud Sync: February 19, 2015 onward [LIKELY BUT UNCONFIRMED]**
- Google Drive sync installed February 19, 2015 — 4 days after USB exfiltration
- ShimCache and Prefetch confirm execution; sync folder created with deleted files
- HOWEVER: deleted sync databases (snapshot.db, sync_config.db) are irrecoverable — no direct evidence that Secret Project documents were uploaded
- drive.google.com hits are browser artifacts, not upload evidence
- Assessment: Google Drive was operational during the exfiltration period and its installation correlates with search history ("google drive", "cloud storage"), but document upload is inferred, not confirmed

**Vector 3 — CD-ROM Optical Media (RM3): March 26, 2015 [CONTENT CONFIRMED, BURNING SOURCE INFERRED]**
- ISO burned one day AFTER final PC cleanup, creating tamper-proof read-only copy
- Content includes IREAP/UMER references matching Secret Project documents
- HOWEVER: isoburn.exe has NO ShimCache or Prefetch entry on informant-PC, meaning no direct execution evidence that the CD was burned on this machine
- The CD could have been burned on a different computer, though content overlap and search history strongly associate it with the suspect
- Research: "cd burning method" (64 hits), "cd burning method in windows" (53 hits), "security checkpoint cd-r" (1 hit)

**Convergence Across 6 Independent Sources:**
1. tsk.timeline/filelist (RM1, RM2): USB filesystem timestamps prove document copies [CONFIRMED]
2. ez.shimcache (PC): Execution timestamps for Google Drive sync and iCloud setup [CONFIRMED execution, INFERRED exfiltration]
3. ez.mft (PC): File creation dates for Google Drive installation [CONFIRMED]
4. evtx.system (PC): USBSTOR driver events linking USB serial numbers to dates [CONFIRMED]
5. exiftool.metadata (RM3): CD-ROM creation timestamp [CONFIRMED]
6. bulk.url_searches (PC): Research queries mapping to each vector [CONFIRMED]

**COUNTER-ANALYSIS ASSESSMENT:**
Vector 1 (USB) remains the strongest evidence with 5+ independent corroborating sources and byte-for-byte file matching. Vector 2 (Google Drive) is downgraded from confirmed to inferred — installation is proven but document upload is not. Vector 3 (CD-ROM) content is confirmed but the burning source machine cannot be definitively established. Despite these qualifications, the overall multi-vector pattern is reinforced by the search history showing deliberate research into each channel type.



### 16. [MEDIUM] Deleted Files on USB Indicate Directory Reorganization and Document Editing

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-02-27T17:20:18 to 2015-03-23T14:38:46 |
| **Sources** | tsk.timeline, tsk.filelist |
| **Evidence Refs** | tc_8fc9c2ee, tc_4f4bb8a4 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Three deleted items were found on the USB device, providing evidence of post-copy activity:

1. **Deleted directory: "Secret Project Data" (inode 2054)** — The root-level directory is marked as deleted (d/d * 2054), while the same data exists under "RM#1/Secret Project Data/". Timeline shows this directory was modified on 2015-02-27 17:20:18, accessed on 2015-03-23 14:32:20, and its birth timestamp set on 2015-03-23 14:32:21. This indicates the files were initially copied under "Secret Project Data/" and later reorganized into "RM#1/Secret Project Data/", with the original root directory deleted around Feb 27 - Mar 23, 2015.

2. **Deleted temp file: ~$ecret_project]_proposal.docx (inode 1030156)** — A 162-byte Microsoft Word lock file was created at 2015-03-23 14:37:52 and modified/accessed at 2015-03-23 14:37:54. This proves the document [secret_project]_proposal.docx was opened for editing in Microsoft Word directly from the USB on March 23, 2015, and then closed (the temp file was deleted upon close).

3. **Orphan file: OrphanFile-5138 (inode 5138, deleted-realloc)** — A 0-byte file with birth timestamp 2015-03-23 14:38:21 and modification/access at 2015-03-23 14:38:46. The close temporal proximity to the Word temp file suggests this may be an artifact of the document editing session.

These deleted artifacts confirm that the USB was not merely used for a one-time copy but was subsequently accessed and files were opened/edited on March 23, 2015.



### 17. [MEDIUM] User "informant" (Iaman Informant) Identified as Primary Account with NIST Email

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:31:01 |
| **Sources** | registry.sam, bulk.email, evtx.windows_system32_winevt_logs_security |
| **Evidence Refs** | tc_3bf1991d, tc_f178d3cf, tc_4197e3ec |
| **ATT&CK** | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |


The SAM registry hive documents 6 user accounts on the system (informant-PC, WORKGROUP):

1. **informant** (RID 1000) — Primary suspect user
2. **admin11** (RID 1001) — Administrative account
3. **ITechTeam** (RID 1002) — IT team account
4. **temporary** (RID 1003) — Temporary account
5. **Administrator** (RID 500) — Built-in administrator (never logged in)
6. **Guest** (RID 501) — Built-in guest (disabled, never logged in)

The "informant" account is the primary user with the most activity. Their email address **iaman.informant@nist.gov** was identified from multiple independent sources:
- Outlook OST file reference carved by bulk_extractor: `Outlook\iaman.informant@nist.gov.ost`
- Multiple Outlook cache file references at `Users/informant/AppData/Local/Microsoft/Outlook/RoamCache/`
- User profile directory structure at `Users/informant/`

This confirms the user's organizational affiliation with NIST (National Institute of Standards and Technology), and the username "informant" is itself notable in a data leakage context.

Security EVTX shows logon events:
- Event 4624 LogonType 2 (Interactive) for "informant" on the local system
- Event 4672 (Special privileges assigned) for admin11 and SYSTEM accounts
- All logons are local — no network logons (Type 3/10) detected from external systems
- Computer name: informant-PC, Domain: WORKGROUP (standalone machine)



### 18. [MEDIUM] RM2 Volume Label "IAMAN $_@" Directly Links Device to Suspect User

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T17:02:36 to 2015-03-24T17:02:36 |
| **Sources** | tsk.filelist, tsk.timeline, bulk.email |
| **Evidence Refs** | tc_5c41657d, tc_defdcda0, tc_c3d20958 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The FAT32 volume label entry on RM2 reads "IAMAN $_@" (inode 3, Volume Label Entry), which directly links this removable media device to the suspect user "Iaman Informant" (identified from the host PC's SAM registry, resignation letter, and Outlook profile as iaman.informant@nist.gov).

The volume label was last modified on Tue Mar 24 2015 17:02:36 according to the MAC timeline, which is the final timestamp on the entire RM2 device — occurring after all files had been deleted. This suggests the volume label may have been modified during or after the cleanup operation.

**Cross-reference with host PC:**
- The host PC's SAM registry shows user account "informant" (RID 1000)
- Resignation letter: "Resignation_Letter_(Iaman_Informant).docx" on the PC desktop
- Email: iaman.informant@nist.gov (from bulk extractor and Outlook profile)
- USBSTOR registry: Two SanDisk Cruzer Fit USB devices connected on 2015-03-24, matching the RM2 deletion timeline

The volume label "IAMAN" is a clear truncation/abbreviation of the suspect's name "Iaman", establishing device ownership. The "$_@" suffix appears to be a personalized identifier.



### 19. [MEDIUM] RM3 Contains Government IT Governance DOCX Document from GovDocs Corpus

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-26T18:35:29 |
| **Sources** | bulk.domain, bulk.exif, bulk.rfc822, bulk.url_services |
| **Evidence Refs** | tc_7639c29f, tc_4d68c925, tc_be590527 |


Bulk_extractor carving from the RM3 E01 image reveals at least one large DOCX (Office Open XML) document containing U.S. government IT governance content sourced from the digitalcorpora.org GovDocs corpus. Document characteristics:

**Content Indicators**:
- References to Federal Enterprise Architecture (FEA) Reference Model
- OMB (Office of Management and Budget) circulars: whitehouse.gov/omb/circulars/a11 and whitehouse.gov/omb/egov/documents/FY09_Ref_Model_Mapping_QuickGuide_July_2007.pdf
- Library of Congress catalog entries (lcweb.loc.gov/cds/train.html, lcweb.loc.gov/rr/print/gm/gra) with descriptions of historical art prints and photographs
- GovDocs corpus self-references: "Govdocs (http://digitalcorpora.org/corpora/govdocs)" appearing at multiple offsets

**Embedded Images (from EXIF data)**:
- 2 images from KODAK DIGITAL SCIENCE DC260 (V01.00) camera, dated 2003-09-24 and 2003-12-10
- 2 images from KODAK DX4530 ZOOM DIGITAL CAMERA, dated 2004-10-07
- 11+ images processed with Adobe Photoshop CS Macintosh, all dated 2006-03-21 (within a 2.5-hour window: 11:19-13:39)
- 3 Corbis stock photos (Artist: "Corbis", one with Microsoft Corporation attribution), original dates 2008-02 and processed 2009-03-12
- Additional images with pro.corbis.com and ns.microsoft.com/photo metadata

**OOXML Structure**:
- schemas.openxmlformats.org/drawingml references at multiple offset clusters (9.8-10 MB and 101-104 MB), indicating rich document formatting
- IEC (www.iec.ch) references at offsets 3.9-9.1 MB, suggesting standards-related content

**Contact Information Embedded in Document**:
- Email: wayne.longman@att.net with HYPERLINK markup
- URL: http://desert-estates.info (also as HYPERLINK)
- Email: mmun@loc.gov (Library of Congress contact, "PREFACE" section)
- "Electronic su[bmission]" text near desert-estates reference

This content is distinct from the "Secret Project" documents found on RM1/RM2, which focus on UMD IREAP/UMER research topics.



### 20. [MEDIUM] PC MFT Contains No Surviving Secret Project Document Traces — Anti-Forensics Cleanup Effective on Local Filesystem

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-25T14:47:40 to 2015-03-25T15:31:01 |
| **Sources** | ez.mft, ez.shimcache, bulk.url_searches |
| **Evidence Refs** | tc_277347e4, tc_9f658671, tc_70f535eb |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/) |


Comprehensive search of the PC's MFT (10,775 windows indexed from ez.mft) for "secret_project" returned zero matches containing Secret Project document filenames. This addresses investigation question Q7: whether Secret Project documents ever existed on the PC's local filesystem.

**Search Results:**
- Query "secret_project" against ez.mft: 0 direct filename matches for [secret_project]_*.docx, [secret_project]_*.pptx, or [secret_project]_*.ppt
- No entries for deleted Secret Project files in PC MFT (no * markers with these filenames)
- No entries in Temp directories matching these document names
- No Word temp files (~$ecret_project*.docx) found on the PC filesystem

**Interpretation:**
Two explanations exist:
1. **Successful anti-forensics**: The Eraser secure deletion tool and CCleaner were both executed on the PC (confirmed by ShimCache, Prefetch, MFT, and EVTX). If Secret Project documents existed on the local filesystem, their MFT entries may have been overwritten by Eraser's secure delete functionality, which targets both file content and metadata. The 2,201 deleted files detected across the PC image, combined with confirmed secure delete tool usage, supports this interpretation.
2. **Direct network/share copy to USB**: The documents may have been copied directly from a network share or email attachment to the USB device without being saved to the PC's local filesystem. However, this is less likely given the bulk copy operation timestamps and the presence of Microsoft Office on the PC.

**Cross-System Context:**
- The documents demonstrably existed on RM1 (original names), RM2 NTFS (original names), RM2 FAT32 (disguised names), and RM3 (carved content) — 4 independent copies across removable media
- The PC shows Google Drive sync folder, Outlook OST references, and Office execution — indicating the user worked with documents locally
- The search history includes "how to delete data", "data recovery tools", and "eraser" — suggesting awareness of and intent to destroy local file traces

**Conclusion:**
The absence of Secret Project document traces in the PC MFT, combined with confirmed anti-forensics tool deployment, is consistent with successful evidence destruction on the local filesystem. The multi-device corroboration from RM1, RM2, and RM3 establishes document possession regardless of local filesystem gaps.



### 21. [MEDIUM] Google Drive Sync Binary Installed February 2015 — Pre-dates Known Exfiltration Timeline

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-02-19T18:24:24 to 2015-03-23T19:56:33 |
| **Sources** | composite.execution, composite.exfil, registry.software, tsk.filelist |
| **Evidence Refs** | tc_92aec3ca, tc_888e99cf, tc_42d82cba |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1537](https://attack.mitre.org/techniques/T1537/) |


Cross-system correlation of ShimCache execution data (composite.execution) with filesystem and MFT evidence reveals that Google Drive sync was installed and executed EARLIER than previously documented:

**ShimCache Execution Evidence (composite.execution):**
- Entry #20: `C:\Program Files (x86)\Google\Drive\googledrivesync.exe` — LastModified: **2015-02-19 18:24:24** — **Executed=Yes**
- Entry #13: `C:\Program Files (x86)\Google\Drive\googledrivesync64.dll` — LastModified: **2015-02-19 18:24:26** — Not executed (DLL, loaded by sync process)
- Entry #67: `C:\Program Files (x86)\Google\Drive\contextmenu64.dll` — LastModified: **2015-02-19 18:24:28** — Not executed (DLL, loaded for Explorer integration)

**Timeline Significance:**
The Google Drive sync binary (`googledrivesync.exe`) was compiled/released on **February 19, 2015** — just 4 days AFTER the bulk copy of Secret Project documents to USB on February 15, 2015. The ShimCache execution flag confirms it was run on the system.

**Cross-System Convergence (4 independent sources):**
1. ShimCache: googledrivesync.exe executed (binary date Feb 19, 2015)
2. Filesystem (tsk.filelist): Google Drive sync folder exists at `Users/informant/Google Drive/` with desktop.ini and a DELETED `happy_holiday.jpg`
3. Filesystem: Google Drive configuration at `Users/informant/AppData/Local/Google/Drive/user_default/` with deleted SQLite databases (snapshot.db inode 75039, sync_config.db inode 75040)
4. Prefetch: GOOGLEDRIVESYNC.EXE-841A0D94.pf confirms execution

**COUNTER-ANALYSIS — Exfiltration Channel Status:**
Google Drive was installed and actively syncing files as early as February 2015, contemporaneous with the USB exfiltration. However, the **specific documents uploaded cannot be determined**: the deleted sync databases (snapshot.db, sync_config.db) are irrecoverable, and the composite.exfil drive.google.com hits (63 windows) are browser artifacts (Chrome API endpoints, gstatic CSS), not document upload evidence. The deleted `happy_holiday.jpg` in the sync folder proves files were synced and then removed, but does not prove Secret Project documents were synced. Google Drive represents a **likely but unconfirmed** secondary exfiltration channel — its installation is corroborated by search history ("google drive", "cloud storage") and its temporal proximity to the USB exfiltration is suggestive, but no direct evidence of document upload exists.



### 22. [MEDIUM] Unresolved Investigation Gaps: Key Artifacts Irrecoverable Due to Anti-Forensics and Extraction Limitations

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T14:32:20 to 2015-03-26T18:35:29 |
| **Sources** | browser.history, ez.jumplists, ez.lnkfiles, ez.shellbags, tsk.filelist |
| **Evidence Refs** | tc_146a400d, tc_5762cf5d, tc_5eef27d2, tc_a734971f |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Cross-system analysis identified eight investigation questions (Q4, Q6, Q8-Q13) that remain partially or fully unresolved due to the convergence of anti-forensics activity and forensic tooling limitations:

**Extraction Failures (13 inode extractions failed):**
The TSK icat tool failed to extract files by inode number for all attempted extractions from the PC disk image, preventing analysis of:
- Google Drive snapshot.db (inode 75039) and sync_config.db (inode 75040) — would prove which files were uploaded to Google Drive (Q4)
- Google Drive sync_log.log (inode 75035) — would contain timestamped upload events (Q8)
- Outlook OST file iaman.informant@nist.gov.ost (inode 46112) — would reveal email attachments and coordination with external recipients (Q9)
- 12 additional disguised files on RM2 FAT32 — file header analysis was impossible, preventing file type identification beyond the 4 confirmed Secret Project copies (Q6)
- Jump List, LNK file, and Shellbag data files — preventing user activity reconstruction (Q11, Q12)

**Anti-Forensics Effectiveness:**
- Browser history databases found but empty — CCleaner cleaned browsing records, preventing timestamp correlation with anti-forensics search queries (Q10)
- Jump Lists/LNK files/Shellbags returned zero windows — anti-forensics cleanup destroyed user activity traces that would have linked file access to specific USB devices (Q11, Q12)

**Tool Limitations:**
- RM3 CD-ROM uses UDF filesystem not supported by TSK — cannot list files, compare content file-by-file, or determine if RM3 contains additional exfiltrated data beyond what bulk_extractor carved (Q13)

**What Remains Proven Despite Gaps:**
Despite these unresolved questions, the core data leakage case is confirmed by multiple independent evidence chains:
- 5 Secret Project documents on RM1 (original names) — confirmed by tsk.filelist
- Same 4 largest documents on RM2 FAT32 (disguised) — confirmed by size matching and OOXML structures
- Same 5 documents on RM2 NTFS (original names) — confirmed by tsk.filelist
- IREAP/UMER content references on RM3 — confirmed by bulk.domain
- USB connection to PC — confirmed by USBSTOR registry and EVTX system log
- Anti-forensics tool usage — confirmed by ShimCache, Prefetch, MFT, and EVTX
- Pre-planned operation — confirmed by search history research queries

The unresolved questions would expand the scope of confirmed exfiltration (Google Drive uploads, additional RM2 files, email communications) but do not alter the core finding of deliberate proprietary data theft via removable media.



### 23. [INFO] USB Media Filesystem Identification: exFAT Volume "Authorized USB" (Serial: 5c75-4d3e)

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.fsstat, tsk.partitions |
| **Evidence Refs** | tc_ebd0cd12, tc_19b0692a |


The removable media device (RM1, image: cfreds_2015_data_leakage_rm1.E01) has the following filesystem characteristics for correlation with USB connection artifacts on the host PC:

- **File System Type**: exFAT (Revision 1.0)
- **Volume Label**: "Authorized USB"
- **Volume Serial Number**: 5c75-4d3e
- **Partition Type**: NTFS/exFAT (MBR type 0x07)
- **Partition Offset**: Sector 32
- **Sector Size**: 512 bytes
- **Cluster Size**: 32,768 bytes (32 KB)
- **Total Sectors**: 7,821,280 (~3.7 GB capacity)
- **Number of FATs**: 1

The volume label "Authorized USB" suggests the device may have been provisioned or labeled to appear as an approved device, potentially to bypass physical security controls or USB device whitelisting policies. This label should be searched for in the host PC's USBSTOR registry keys, setupapi logs, and Windows event logs to confirm the device was connected to the suspect's workstation.



### 24. [INFO] Document Metadata Contains University of Maryland (UMD) References

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Time** | 2014-12-04T11:24:50 to 2015-01-23T15:47:10 |
| **Sources** | bulk.url, bulk.url_services, bulk.domain |
| **Evidence Refs** | tc_04df8669, tc_317f278a, tc_64a9a930 |


Bulk extractor analysis of the USB media carved URLs and domains embedded within the Office documents that reference an academic/research institution:

- **http://www.ireap.umd.edu/umer** — University of Maryland, Institute for Research in Electronics and Applied Physics (IREAP), specifically the UMER (University of Maryland Electron Ring) project. Context shows "Website: http://www.ireap.umd.edu/umer" followed by "Publications:"
- **http://www.umer.umd.edu/** — The UMER project's direct website

These URLs appear at byte offsets 29257412 and 29257456 in the disk image, embedded within the proposal documents (which are the largest files on the media at 35.2 MB and 6.5 MB).

Additionally, **http://digitalcorpora.org/corpora/govdocs** references appear in the documents (20 occurrences, 18 in UTF-16 encoding), along with text "one of Govdocs (http://digitalcorpora.org/corpora/govdocs) The first page" — indicating some document content may have been sourced from GovDocs corpus documents.

The remaining carved URLs are benign document metadata: Adobe XAP/EXIF/TIFF/Photoshop namespace URIs (embedded images metadata), OpenXML schema references (Office document format), Apple plist DTDs (embedded images from macOS), and IEC color profile references. No email addresses were carved from the media.

No suspicious upload/exfiltration service URLs (Mega, Pastebin, Dropbox, etc.) were identified on the USB device itself.



### 25. [INFO] No Steganographic Content or Malware Detected on Removable Media

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | bulk.url, bulk.domain, bulk.url_services |
| **Evidence Refs** | tc_c1581d3e, tc_e2e2e7c0, tc_f1417a27 |


Automated scans of the removable media (RM1) returned negative results for:

1. **Steganography**: The steganography detection scan (stegdetect) of image files on the media found no hidden content. The Office documents contain embedded JPEG images with standard Adobe/Photoshop XMP metadata (EXIF, TIFF tags), but no steganographic payloads were detected.

2. **YARA malware signatures**: The YARA file scan against the signature-base ruleset (~4,000 rules) produced no matches, indicating the files on the USB are standard Office documents without embedded malware, macros, or known malicious patterns.

3. **Email addresses**: No email addresses were carved from the USB media by bulk_extractor, indicating the documents do not contain embedded email communications or contact information that would directly reveal the intended recipient of the exfiltrated data.

These negative results are significant: the USB media appears to be a straightforward data exfiltration device containing only the stolen proprietary documents, without additional concealment mechanisms (steganography) or malicious payloads. The threat is data theft, not malware deployment.



### 26. [INFO] No Encryption or Compression Tools Used for Data Staging — Direct USB Copy Method

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | ez.shimcache, tsk.filelist |
| **Evidence Refs** | tc_9f658671, tc_8ab42c01, tc_0b6a8554 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Analysis of the disk image, ShimCache execution history, and file system metadata finds no evidence that encryption or file compression tools were used to stage data for exfiltration:

**No Archive/Compression Tools:**
- ShimCache (292 entries): No entries for WinZip, WinRAR, 7-Zip, tar, gzip, or any compression utility
- Filesystem search: No .zip, .rar, .7z, .tar, .gz, or .bz2 archive files found on the PC disk image
- No archive files found in temporary directories, Downloads, Desktop, or the Recycle Bin
- The exfiltrated files on the USB media are uncompressed Office documents (PPT, PPTX, DOCX)

**No Encryption Tools:**
- ShimCache: No entries for VeraCrypt, TrueCrypt, BitLocker, GnuPG, or other encryption utilities
- The USB media (RM1) uses a standard exFAT filesystem with no encryption layer
- The exfiltrated documents on USB are not encrypted

**Data Staging Method:**
The exfiltration was performed as a direct bulk file copy to the USB device. The USB filesystem timeline shows all 5 documents (74 MB total) were copied within a 42-second window on February 15, 2015, consistent with a simple drag-and-drop or file copy operation.

**Anti-Forensics Distinction:**
While the suspect used CCleaner and Eraser (anti-forensics/cleanup tools), these were used for trace DELETION, not for encrypting or compressing the exfiltrated data itself. The data was taken in its original, unprotected format.



### 27. [INFO] RM2 Personal Image Files with EXIF Metadata — Kodak Camera Photos from 2003-2013

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2003-09-24T15:33:42 to 2015-03-23T16:55:37 |
| **Sources** | tsk.timeline, bulk.exif |
| **Evidence Refs** | tc_defdcda0, tc_e1cd0ea8 |


RM2's FAT32 partition contained 22 deleted personal image files (photographs) as orphan files at the root level, with EXIF metadata and modification dates spanning 2004-2013. These appear to be the suspect's personal photo collection stored alongside the disguised work documents.

**EXIF metadata extracted from RM2 by bulk_extractor:**
- Camera: Eastman Kodak Company, KODAK DIGITAL SCIENCE DC260 (V01.00)
- Photo dates: 2003:09:24 15:33:42 (earliest), additional dates from 2009
- Resolution: 1536x1024 (1.5 megapixels), later photos at 2580x1932
- Color space: sRGB
- Flash: not fired on some images

**Image files and modification timestamps (from MAC timeline):**
- CUTTY-~1.JPG (1,625,241 bytes) — Oct 14 2004
- STONEH~1.JPG (1,236,401 bytes) — Oct 14 2004 (Stonehenge reference)
- SPQR.JPG (897,275 bytes) — Oct 14 2004 (Roman reference)
- pisa.JPG (847,709 bytes) — Apr 10 2005 (Pisa, Italy)
- PIAZZA~1.JPG (1,267,394 bytes) — Apr 10 2005 (Italian piazza)
- leaf.jpg, oak-snow.jpg — Jan 24 2010
- BAMBOO~1.GIF, barn.gif, cactus.png, cave.png, eggs.gif, FORSYT~1.PNG, orchid.png — Jan 22 2013
- jump.jpg — Mar 17 2013
- boudicca.bmp, blini.gif, injera.gif, tomatoes.gif, tapas.gif, wat.gif, amalfi.bmp, JACK-O~1.TIF — May 07 2013

**Location indicators from filenames:** amalfi (Italy), pisa (Italy), PIAZZA (Italy), SPQR (Rome), STONEH~1 (Stonehenge, UK), boudicca (UK), wat (Thailand?) — suggesting European/international travel.

**Forensic significance:** All 22 images were accessed on Mon Mar 23 2015 00:00:00 (date-only precision) and deleted with birth timestamps clustering at Mar 23 2015 16:55:17-16:55:37. The presence of personal photos mixed with disguised work documents is consistent with the device being a personal USB drive repurposed for data exfiltration. The personal content may also have been placed to provide plausible cover if the device were discovered.



### 28. [INFO] RM3 Media Identification: CD-ROM with UDF Filesystem

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-26T18:35:29 |
| **Sources** | exiftool.metadata |
| **Evidence Refs** | tc_c007c848 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Removable Media #3 (RM3) is a CD-ROM disc with a UDF v5.13 filesystem, physically distinct from the USB flash drives used for RM1 and RM2. Key characteristics from the FTK Imager acquisition log:

- **Device**: HL-DT-ST DVD+-RW GT80N (optical drive)
- **Media Type**: CD-ROM
- **Bytes per Sector**: 2,048
- **Sector Count**: 52,514 (~107.5 MB capacity)
- **Session Count**: 1
- **Filesystem**: UDF Version 5.13
- **Acquisition Tool**: AccessData FTK Imager 3.3.0.5
- **ISO File Modified**: 2015-03-26 18:35:29 UTC

The UDF filesystem is not supported by The Sleuth Kit (TSK), causing failures in mmls, fls, mactime, foremost, and MFT parsing tools. fsstat returned 0 windows. This limits forensic analysis to content-carving tools (bulk_extractor, strings, PhotoRec, ExifTool, YARA).

The ISO creation date of March 26, 2015 is notable in the investigation timeline — it falls one day after the final anti-forensics cleanup activity observed on the source PC (March 24-25, 2015), suggesting the disc was burned after evidence cleanup on the PC.



### 29. [INFO] RM3 Indicators of Compromise: Email Addresses, URLs, and Contact Information

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | bulk.email, bulk.domain, bulk.url |
| **Evidence Refs** | tc_4a98a1ac, tc_7639c29f |


Bulk_extractor carved the following IOCs from the RM3 E01 image, embedded within document content:

**Email Addresses** (bulk.email, source_id 62):
- Eric_P._Lauer@omb.eop.gov (offset 53407872) — OMB/Executive Office of the President email, associated with "Lauer" contact name
- wayne.longman@att.net (offsets 53510872, 53510897, 53518234, 53518312, 53541970) — Personal email with HYPERLINK markup in document, also appears in UTF-16 encoding
- mmun@loc.gov (offset 102175202) — Library of Congress email, appears in document PREFACE section

**Domains** (bulk.domain, source_id 61):
- omb.eop.gov — Executive Office of the President
- att.net — AT&T consumer email
- loc.gov — Library of Congress
- desert-estates.info/inf — Real estate website, linked as HYPERLINK
- whitehouse.gov — White House (OMB circulars and e-gov documents)
- digitalcorpora.org — GovDocs corpus source
- lcweb.loc.gov — Library of Congress web resources
- pro.corbis.com — Corbis stock photography (image metadata)
- ns.microsoft.com — Microsoft photo metadata namespace
- www.apple.com — Apple DTD references (document/image processing origin)

**URLs of Interest** (bulk.url, source_id 65):
- http://www.whitehouse.gov/omb/egov/documents/ — Federal e-government documents
- http://www.whitehouse.gov/omb/circulars/a — OMB circulars
- http://desert-estates.info — Personal/real estate URL in HYPERLINK
- http://digitalcorpora.org/corpora/govdocs — GovDocs corpus identifier
- http://lcweb.loc.gov/cds/train.html — Library of Congress cataloging
- http://www.ireap.umd.edu/umer — UMD IREAP research reference

The wayne.longman@att.net email and desert-estates.info URL appear together in HYPERLINK markup within document content, suggesting they are author/contact information embedded in one of the GovDocs documents. The Eric_P._Lauer@omb.eop.gov email is associated with government budget documentation content.



### 30. [INFO] RM3 Negative Findings: No Malware, Steganography, Deleted Files, or Anti-Forensics Detected

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | photorec.report, exiftool.metadata |
| **Evidence Refs** | tc_756e2038, tc_c007c848 |


Multiple forensic tools produced negative results on RM3, which is significant both for ruling out threats and for understanding the media's forensic profile:

**File Recovery**:
- PhotoRec recovered 0 files from the RM3 image. This is expected for a UDF-formatted CD-ROM where file carving from the raw image yielded no separable file signatures outside the document container.

**Malware/Threat Detection**:
- YARA scanning with signature-base ruleset (~4,000 rules): No matches detected
- No suspicious executables or scripts identified in strings output

**Steganography**:
- Stegdetect/steganography scanning produced no positive detections on embedded image content

**Filesystem Analysis Limitations** (due to UDF):
- TSK mmls: Failed (no recognized partition table on optical media)
- TSK fls: Failed (UDF not supported — cannot list files or detect deleted entries)
- TSK mactime: Failed (no bodyfile available)
- TSK foremost: Failed
- TSK fsstat: 0 windows (empty output)
- MFT parser: Failed (no NTFS MFT on UDF media)

**Anti-Forensics Assessment**:
- CD-ROM is inherently read-only media — no post-write modification, deletion, or timestomping is possible on the disc itself
- No evidence of anti-forensics tools targeting optical media
- However, the disc was burned on 2015-03-26, after PC cleanup activity on March 24-25, which could represent data preservation/exfiltration after cleanup rather than anti-forensics on the disc itself

**Consistency Across Image Formats**:
- The E01 and ISO images are different acquisition formats (FTK Imager E01 vs raw ISO) of the same physical CD-ROM
- Both represent the same 52,514 sectors of UDF content
- ExifTool reports "File format error" on the ISO, consistent with UDF being an unsupported format for ExifTool's ISO parser



### 31. [INFO] RM3 Document Metadata Indicates Mac/Apple Authoring Environment

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | bulk.exif, bulk.domain |
| **Evidence Refs** | tc_4d68c925, tc_7639c29f |


EXIF metadata carved from embedded images on RM3 reveals the document(s) were created or edited in an Apple Macintosh environment, with images processed through Adobe Photoshop CS:

**Adobe Photoshop CS Macintosh Images** (11 instances, all dated 2006-03-21):
- Software: "Adobe Photoshop CS Macintosh"
- Processing timestamps span 2.5 hours: 11:19:46 to 13:39:22 on March 21, 2006
- Resolution: 60 DPI (consistent with screen/web graphics, not print)
- Varying dimensions (157x207 to 539x273 pixels) — consistent with document illustrations/diagrams
- SHA1 hashes present for each image (e.g., a41bab08fd5f7a4329a0362a16221a8e358b9332)

**Kodak Camera Photos**:
- KODAK DIGITAL SCIENCE DC260 (V01.00): 2 images, dated 2003-09-24 and 2003-12-10
  - Resolution: 1536x1024 pixels, 72 DPI
  - This same camera model (DC260) also appears in RM2 evidence, creating a cross-media link
- KODAK DX4530 ZOOM DIGITAL CAMERA: 2 images, both dated 2004-10-07
  - Resolution: 2580x1932 pixels, 230 DPI

**Corbis Stock Photos**:
- 2 images with Artist: "Corbis", original dates 2008-02-11 and 2008-02-18, processed 2009-03-12
- 1 image with implicit Microsoft Corporation attribution, original date 2008-02-07, processed 2009-03-12
- Source: pro.corbis.com (stock photography service)

**Apple Platform Indicators**:
- www.apple.com DTD references at multiple offsets (95024989, 95065517, etc.) — Apple Property List format
- Adobe Photoshop CS specifically labeled "Macintosh" variant
- Combined with ns.adobe.com XMP metadata namespaces

The image metadata spans 2003-2009, indicating the document content predates the 2015 data leakage incident and represents pre-existing government documents assembled from various sources over time.



### 32. [INFO] No Malicious Timestomping — Root MFT Entry Discrepancy is Benign OS Artifact

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | forensic.timestomping |
| **Evidence Refs** | tc_b2cfa91a |


MFT timestamp analysis (forensic.timestomping) detected only ONE entry with $STANDARD_INFORMATION vs $FILE_NAME timestamp discrepancy:

**Detection:**
- File: `.\\` (root directory MFT entry)
- $SI Created: **2009-07-14 03:38:53** (original Windows 7 installation date)
- $FN Created: **2015-03-25 19:49:59** (date of disk cleanup activity)
- Gap: 2,080 days

**Assessment: FALSE POSITIVE — Benign OS Artifact**
The root directory MFT entry's $FILE_NAME timestamp was updated during disk maintenance/cleanup activity on March 25, 2015 — the SAME day as documented Eraser and CCleaner cleanup operations. This is a well-known NTFS artifact where disk defragmentation, chkdsk, or certain cleanup tools cause $FN timestamp updates on the root entry. The $SI timestamp correctly reflects the original Windows 7 installation (July 14, 2009 — the standard Windows 7 RTM date).

**Significance:**
- No evidence of malicious timestomping on any user files
- The subject did NOT attempt to backdate or modify file timestamps to conceal exfiltration activity
- Anti-forensics efforts were focused on file DELETION (Eraser) and artifact CLEARING (CCleaner) rather than timestamp manipulation
- This is consistent with the insider threat profile: the subject had legitimate file access timestamps and did not need to disguise when files were created or modified



### 33. [INFO] No Lateral Movement or External Compromise — Insider-Only Attack Pattern

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | composite.lateral_movement, composite.defense_evasion, composite.file_staging, composite.persistence, forensic.timestomping |
| **Evidence Refs** | tc_d8a4bbe6, tc_b2cfa91a, tc_92aec3ca |
| **ATT&CK** | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |


Cross-system correlation analysis confirms the absence of external intrusion or lateral movement indicators, establishing this as a pure insider threat case:

**Evidence of Absence (Multiple Independent Sources):**
1. **composite.lateral_movement**: 0 windows — no network logon events (Event ID 4624 Type 3/10), no RDP sessions, no WinRM activity, no SMB lateral movement
2. **composite.defense_evasion**: 0 windows — no log clearing events (Event IDs 104, 1102), no hidden processes, no disabled security tools
3. **composite.file_staging**: 8 windows — all standard Windows system files (WinSxS, MSOCache, .NET Framework installers), no suspicious staging archives in temp directories
4. **composite.persistence**: 58 windows — all standard Windows services and registry entries, no malicious persistence mechanisms
5. **forensic.timestomping**: 1 window — only benign root directory MFT artifact, no file timestamp manipulation

**Attack Pattern Assessment:**
The subject operated entirely within their legitimate access scope:
- Used authorized local user account "informant" (no privilege escalation needed)
- Accessed files through standard file explorer operations
- Exfiltrated via physical removable media (USB drives, CD-ROM) and potentially Google Drive
- Anti-forensics limited to file deletion (Eraser) and artifact clearing (CCleaner)
- No attempt to establish remote access, backdoors, or persistent implants

This pattern is characteristic of an opportunistic insider with authorized access who used only built-in or commonly available tools, rather than an external threat actor or a sophisticated espionage operation.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No network IOCs extracted | | |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Program` |  | Google Drive Sync Binary Installed February 2015 — Pre-dates Known Exfiltration  |
| Path | `/Windows/Recent/AutomaticDestinations/` |  | CCleaner Effectively Destroyed Browser History, Jump Lists, LNK Files, and Shell |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `iaman.informant@nist.gov` |  | User "informant" (Iaman Informant) Identified as Primary Account with NIST Email |
| Email | `wayne.longman@att.net` |  | RM3 Contains Government IT Governance DOCX Document from GovDocs Corpus |
| Email | `mmun@loc.gov` |  | RM3 Contains Government IT Governance DOCX Document from GovDocs Corpus |




---

## Appendix C: MITRE ATT&CK Coverage

12 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (1) > Privilege Escalation (1) > Defense Evasion (5) > Discovery (1) > Collection (2) > Exfiltration (3) > Impact (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Suspect User "Iaman Informant" Identified with...; User "informant" (Iaman Informant) Identified...; No Lateral Movement or External Compromise —... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Suspect User "Iaman Informant" Identified with...; User "informant" (Iaman Informant) Identified...; No Lateral Movement or External Compromise —... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Suspect User "Iaman Informant" Identified with...; User "informant" (Iaman Informant) Identified...; No Lateral Movement or External Compromise —... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | RM2 Contains Disguised Copies of Secret... |
| [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | Masquerade File Type | RM2 Contains Disguised Copies of Secret...; RM2 NTFS Partition Contains Secret Project... |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | CCleaner Effectively Destroyed Browser... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Anti-Forensics Tools Downloaded, Installed,...; ShimCache Execution Timeline: Anti-Forensics...; Systematic Deletion of All Files on RM2 —...; Premeditated Anti-Forensics Research: Search...; Coordinated Multi-Device Evidence Destruction...; PC MFT Contains No Surviving Secret Project...; CCleaner Effectively Destroyed Browser...; Unresolved Investigation Gaps: Key Artifacts... |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Suspect User "Iaman Informant" Identified with...; User "informant" (Iaman Informant) Identified...; No Lateral Movement or External Compromise —... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1518](https://attack.mitre.org/techniques/T1518/) | Software Discovery | Premeditated Anti-Forensics Research: Search... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Proprietary "Secret Project" Documents...; Two SanDisk Cruzer Fit USB Devices Connected...; RM2 NTFS Partition Contains Secret Project...; USB Device Serial Numbers Mapped to Connection...; Multi-Vector Exfiltration Strategy: USB,... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Cross-Media Correlation: Secret Project...; CD-ROM Burning Research Corroborates RM3 as...; Multi-Vector Exfiltration Strategy: USB,... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Proprietary "Secret Project" Documents...; Deleted Files on USB Indicate Directory...; Two SanDisk Cruzer Fit USB Devices Connected...; No Encryption or Compression Tools Used for...; RM2 Contains Disguised Copies of Secret...; RM2 Volume Label "IAMAN $_@" Directly Links...; RM2 NTFS Partition Contains Secret Project...; RM3 Media Identification: CD-ROM with UDF Filesystem; Cross-Media Correlation: Secret Project...; Premeditated Anti-Forensics Research: Search...; USB Device Serial Numbers Mapped to Connection...; CD-ROM Burning Research Corroborates RM3 as...; Coordinated Multi-Device Evidence Destruction...; Multi-Vector Exfiltration Strategy: USB,... |
| [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | Google Drive Sync Binary Installed February... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | ShimCache Execution Timeline: Anti-Forensics...; Premeditated Anti-Forensics Research: Search...; Google Drive Sync Binary Installed February...; Multi-Vector Exfiltration Strategy: USB,... |


### Impact

| Technique | Name | Findings |
|-----------|------|----------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Anti-Forensics Tools Downloaded, Installed,...; ShimCache Execution Timeline: Anti-Forensics...; Systematic Deletion of All Files on RM2 —...; Coordinated Multi-Device Evidence Destruction...; PC MFT Contains No Surviving Secret Project... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 723 |
| Findings submitted | 33 |
| Confirmed | 29 |
| Inferences | 4 |
| Input tokens | 84.1K |
| Output tokens | 246.2K |
| Total tokens | 330.3K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 84.0K | 243.4K | 327.4K |
| claude-sonnet-4-5@20250929 | 54 | 2.8K | 2.9K |




<details>
<summary>Evidence Sources (88)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.filelist | sleuthkit | 27 |
| bulk.domain | bulk_extractor | 189 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| tsk.fsstat | sleuthkit | 37 |
| exiftool.metadata | exiftool | 9 |
| tsk.timeline | sleuthkit | 67 |
| tsk.partitions | sleuthkit | 10 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p2 | sleuthkit | 93 |
| bulk.domain | bulk_extractor | 366644 |
| bulk.email | bulk_extractor | 6532 |
| bulk.ether | bulk_extractor | 6 |
| bulk.ip | bulk_extractor | 43 |
| bulk.packets | bulk_extractor | 760 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.tcp | bulk_extractor | 19 |
| bulk.url | bulk_extractor | 421750 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| chainsaw.hunt | chainsaw | 2 |
| evtx.manifest | evtx-extract | 53 |
| ez.mft | eztools | 98918 |
| ez.shimcache | eztools | 307 |
| registry.default | regripper | 418 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
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
| evtx.windows_system32_winevt_logs_security | eztools | 285 |
| evtx.windows_system32_winevt_logs_application | eztools | 959 |
| evtx.windows_system32_winevt_logs_system | eztools | 1349 |
| tsk.filelist | sleuthkit | 51 |
| tsk.filelist | sleuthkit | 51 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist.p2 | sleuthkit | 43 |
| tsk.filelist.p2 | sleuthkit | 43 |
| bulk.domain | bulk_extractor | 7295 |
| bulk.email | bulk_extractor | 26 |
| bulk.exif | bulk_extractor | 27 |
| bulk.ip | bulk_extractor | 7 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7192 |
| bulk.url_services | bulk_extractor | 58 |
| bulk.zip | bulk_extractor | 5221 |
| tsk.timeline | sleuthkit | 187 |
| tsk.fsstat | sleuthkit | 0 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| photorec.report | photorec | 2 |
| strings.output | strings | 34815 |
| exiftool.metadata | exiftool | 29 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.timeline | composite | 176 |
| composite.execution | composite | 122 |
| composite.persistence | composite | 2174 |
| composite.recovery | composite | 22 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 290 |
| composite.exfil | composite | 2320 |
| enrichment.iocs | enrichment | 58 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
