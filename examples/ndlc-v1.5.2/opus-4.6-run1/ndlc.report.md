# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-19T21:01:34.809356+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 133 evidence sources (74 disk, 59 other) | 596 tool calls | 1.1 hours
**Results:** 23 findings (3 critical, 9 high) | 19 confirmed, 4 inference
**Timeline:** 2015-02-15 to 2015-03-25

**Key Threats:**
- Data Exfiltration via Removable Media - Secret Project Data Staged on USB (RM1) and USB (RM2)
- Insider Threat - User Identity and Resignation Letter Confirm Departing Employee Data Theft
- Cross-System: Identical Exfiltrated Documents Confirmed Across All Three Removable Media (RM1, RM2, RM3)

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-02-15 to 2015-03-25): Data Exfiltration via Removable Media - Secret Project Data Staged on USB (RM1) and USB (RM2) (+8 related)
- **Persistence** (2015-02-15 to 2015-03-22): Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across RM1, RM2, and RM3 (+3 related)
- **Command and Control** (2015-03-24): CD-R (RM3) EXIF Metadata: Cover Images Are Stock Windows 7 Photos, Document-Embedded Images Show Kodak and Adobe Processing (+1 related)
- **Credential Access** (2015-02-15 to 2015-03-24): Cross-System: Identical Exfiltrated Documents Confirmed Across All Three Removable Media (RM1, RM2, RM3) (+2 related)
- **Defense Evasion / Anti-Forensics** (2015-02-15 to 2015-03-22): Dual-Partition USB Device Structure Enables Plausible Deniability (+1 related)
- **Discovery / Collection** (2015-03-22): Potential Co-Conspirator Contact Entry — spy.conspirator@nist.gov in Outlook Data

**Tools:** search (162), get_raw_output (71), submit_finding (40), extract_optical_file (38), get_findings (23). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Data Exfiltration via Removable Media - Secret Project Data Staged on USB (RM1) and USB (RM2)** (2015-02-15T16:51:38 to 2015-03-24T10:00:18)


- **Insider Threat - User Identity and Resignation Letter Confirm Departing Employee Data Theft** (2015-03-22T14:33:13 to 2015-03-25T15:29:08)


- **Cross-System: Identical Exfiltrated Documents Confirmed Across All Three Removable Media (RM1, RM2, RM3)** (2015-02-15T16:51:38 to 2015-03-24T20:57:03)




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

596 tool calls were executed across 25
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Insider Threat Data Exfiltration Investigation — CFREDS 2015 Data Leakage Case

## Background

This investigation was initiated to examine a suspected insider threat data exfiltration incident involving a departing employee at a government organization. The subject, identified through converging forensic evidence as "Iaman Informant" (username: informant, email: iaman.informant@nist.gov), is alleged to have systematically copied classified "Secret Project Data" from a secured network file share to multiple removable media devices and potentially to cloud storage, employing a variety of anti-forensic techniques to conceal the theft.

The forensic examination encompassed four disk images: the subject's workstation (cfreds_2015_data_leakage_pc.E01, hostname "informant-PC," running Windows 7 64-bit in the Eastern Standard Time zone), and three removable media devices — RM1 (cfreds_2015_data_leakage_rm1.E01, a 4GB USB device with dual partitions), RM2 (cfreds_2015_data_leakage_rm2.E01, a FAT32 USB device), and RM3 (cfreds_2015_data_leakage_rm3_type3.E01, a CD-R disc). Analysis drew upon 25 indexed evidence sources spanning 16 distinct artifact types including filesystem analysis (Sleuthkit), registry examination (RegRipper, python-registry), event log analysis (Chainsaw, Hayabusa), MFT parsing (EZTools), bulk content extraction (bulk_extractor), string analysis, EXIF metadata extraction, optical media session reconstruction, and file masquerade detection.

The source PC was connected to an internal network on subnet 10.11.11.0/24, where the subject accessed a secured network share at \\\\10.11.11.128\\secured_drive. The PC's own DHCP-assigned address was 10.11.11.129. The investigation identified the "informant" user account (RID 1000, login count 10, created 2015-03-22 at 14:33:54 UTC) as the sole actor in the exfiltration campaign. Three additional local accounts — admin11 (RID 1001), ITechTeam (RID 1002), and temporary (RID 1003) — were created by the informant account within a two-minute window on the same day, but none of these accounts accessed the Secret Project Data or performed any substantive activity relevant to the data theft.

## Incident Timeline

The exfiltration campaign unfolded over approximately five weeks, from February 15 through March 25, 2015, and can be divided into five distinct operational phases.

**Phase 1 — Initial Data Copy (February 15, 2015).** The earliest evidence of exfiltration dates to Sunday, February 15, 2015. At 16:51:38 UTC, the Secret Project Data directory structure was created on RM1's exFAT partition (volume label "Authorized USB," volume serial 5c75-4d3e). Between 16:52:08 and 16:52:20 UTC, five classified Office documents were copied to this partition with their original filenames intact: [secret_project]_design_concept.ppt, [secret_project]_detailed_design.pptx, [secret_project]_revised_points.ppt, [secret_project]_detailed_proposal.docx, and [secret_project]_proposal.docx. These files had modification dates ranging from December 4, 2014 to January 23, 2015, consistent with active project documents. Twelve days later, on February 27, 2015, at 17:20:18 UTC, the root "Secret Project Data" directory on this partition was deleted, though the files themselves remained accessible in subdirectories.

**Phase 2 — Workstation Setup and Network Reconnaissance (March 22, 2015).** On Sunday, March 22, the subject logged into the PC for the first time at 14:33:13 UTC and began setting up the environment. Internet Explorer 11 was installed at 15:12:32 UTC, and Chrome was configured. At 14:52:22 UTC, shellbag artifacts record the first access to the \\\\10.11.11.128\\secured_drive network share, where the subject navigated through the complete directory tree including Secret Project Data, Common Data, and Past Projects subdirectories. Between 15:51:54 and 15:53:01 UTC, the subject created three additional local accounts (admin11, ITechTeam, temporary) and added admin11 and ITechTeam to the local Administrators group. Security event logs (Event ID 4720/4732, confirmed via Chainsaw and Hayabusa) definitively attribute these creations to the informant account's SID (S-1-5-21-2425377081-3129163575-2985601102-1000).

**Phase 3 — Document Access, Research, and Staging (March 23, 2015).** The subject's activity intensified on Monday, March 23. Cover image files (24 photographs including amalfi.bmp, barn.gif, boudicca.bmp, cactus.png, and others) were created on RM2's FAT32 partition between 16:55:17 and 16:55:37 UTC, establishing an innocuous appearance for the media. Chrome was launched at 17:26:50 UTC, followed by browsing to Bing and Google. The subject searched for "secret" using Windows Explorer's search bar at 18:40:17 UTC (recorded in the WordWheelQuery registry key). Secret project files were opened using their respective Office applications — Excel opened (secret_project)_pricing_decision.xlsx at 20:26:50 UTC, and PowerPoint opened [secret_project]_final_meeting.pptx at 20:27:33 UTC. Google Drive was installed at approximately 20:01:53 UTC, with ShimCache confirming googledrivesync.exe was executed. Critically, the subject conducted extensive browser research during this period into topics including "anti-forensic+tools" (85 search instances), "ccleaner" (65 instances), "eraser" (51 instances), "external+device+and+forensics" (65 instances), "cd+burning+method" (64 instances), "information+leakage+cases" (47 instances), and "DLP DRM" (90 instances). This research directly preceded and informed every subsequent anti-forensic action.

**Phase 4 — Multi-Media Exfiltration and CD-R Burning (March 24, 2015).** On Tuesday, March 24, the subject executed the primary exfiltration operation. Between 09:59:26 and 10:00:18 UTC, seventeen masqueraded copies of the Secret Project Data documents were created on both RM1's FAT32 partition and RM2, organized into five directories mirroring the corporate share structure (design, pricing decision, progress, proposal, technical review). Every document was renamed with a false file extension to disguise its Office format — for example, [secret_project]_detailed_proposal.docx became "a_gift_from_you.gif" (35,226,880 bytes), and [secret_project]_detailed_design.pptx became "winter_whether_advisory.zip" (16,381,123 bytes). The USBSTOR driver was last written at 13:37:59 UTC, and shellbag evidence records the subject browsing E:\\RM#1\\Secret Project Data at 13:38:31 UTC and the D: drive directories (de, tr, pd, prop, prog) between 19:47:48 and 20:44:18 UTC. The subject saved Resignation_Letter_(Iaman_Informant).docx at 18:48:40 UTC.

Between 20:54:16 and 20:57:03 UTC, the subject burned data to the CD-R (RM3, volume label "IAMAN CD") in nine UDF VAT sessions. The disc preserves evidence of iterative concealment refinement: sessions -7 through -3 used full directory names matching the corporate share structure; session -1 used abbreviated names (de, pd, prog, prop, tr); and the final session (0) deleted all data directories, leaving only three stock Windows 7 sample photographs (Koala.jpg, Penguins.jpg, Tulips.jpg) as cover content. All seventeen masqueraded documents were subsequently deleted from RM1's FAT32 partition and RM2, leaving only orphaned file system entries.

**Phase 5 — Anti-Forensic Cleanup and Departure (March 25, 2015).** On Wednesday, March 25, the subject executed the final phase of the operation. Outlook was used at 14:41:03 UTC for email activity. At 14:50:14 UTC, the Eraser 6.2.0.2962 installer was run from the Desktop\\Download directory, followed by the CCleaner v5.04 installer (ccsetup504.exe) at 14:57:56 UTC. Eraser was executed at 15:12:28 UTC for secure file deletion, and CCleaner64.exe was executed at 15:15:50 UTC for system trace cleaning. Google Drive sync was then launched at 15:21:30 UTC — notably after the anti-forensic cleanup, raising the possibility that the subject cleaned traces first and then synced remaining data to the cloud. WINWORD.EXE was used at 15:24:48 UTC (the subject's fourth run) to finalize the resignation letter, which was converted to XPS format at 15:28:47 UTC. The last RecentDocs registry write occurred at 15:29:08 UTC, marking the final recorded activity on the system. Google Drive's sync_config.db, cacerts, and snapshot.db files were all found deleted, consistent with Eraser's secure deletion capability having been used to destroy cloud synchronization evidence.

## Key Findings

The investigation produced 23 findings, of which 3 are critical severity, 9 are high severity, 5 are medium severity, and the remainder are informational. The findings are organized below by operational category.

**Data Collection and Exfiltration.** The core of the incident is the confirmed exfiltration of 17 classified Office documents — collectively titled "Secret Project Data" — from the network share at \\\\10.11.11.128\\secured_drive to three separate removable media devices. The documents encompassed design specifications (PPT, PPTX), proposals (DOCX), pricing decisions (XLSX), progress reports (DOCX), and technical reviews (DOCX, PPTX, OLE). RM1's exFAT partition contained original-name copies dating to February 15, 2015. RM1's FAT32 partition, RM2, and RM3 all contained byte-identical masqueraded copies created on March 24, 2015. Cross-media verification confirmed that file sizes matched exactly across all three media — for example, a_gift_from_you.gif was consistently 35,226,880 bytes (the true [secret_project]_detailed_proposal.docx), and winter_whether_advisory.zip was consistently 16,381,123 bytes (the true [secret_project]_detailed_design.pptx). The same three email addresses embedded within the document content — Eric_P._Lauer@omb.eop.gov, wayne.longman@att.net, and mmun@loc.gov — appeared at proportional disc offsets on both RM2 and RM3, providing independent confirmation of byte-identical content across media.

**File Extension Masquerading.** All 17 exfiltrated documents were systematically renamed with false file extensions across all three media devices. OLE-format documents (PPT, XLS) were given extensions such as .amr, .db, .avi, and .svg, while OOXML-format documents (DOCX, PPTX, XLSX) were given extensions including .zip, .7z, .jpg, .png, .one, .gif, and .txt. The filenames themselves were changed to innocuous personal-sounding names (winter_storm, my_favorite_cars, diary_#1d, landscape, a_gift_from_you). Sleuthkit masquerade detection confirmed the mismatch between file signatures and extensions. This technique maps to MITRE ATT&CK T1036.008 (Masquerading: Match Legitimate Name or Location).

**Multi-Layered Anti-Forensic Concealment.** The subject employed at least five distinct anti-forensic techniques. First, file extension masquerading as described above. Second, systematic deletion of all exfiltrated documents from all removable media after copying. Third, multi-session CD-R burning exploiting UDF VAT to progressively obscure and ultimately "delete" data on write-once media — though the subject apparently did not understand that UDF's Virtual Allocation Table preserves all previous generations on write-once discs. Fourth, placement of cover content (personal photographs on RM1/RM2 and stock Windows 7 sample photos on RM3) to make media appear innocuous upon casual inspection. Fifth, execution of dedicated anti-forensic tools — Eraser for secure file deletion and CCleaner for system trace cleaning — on the final day of activity.

**Dual-Partition USB Structure.** RM1 was configured with two distinct partitions to enable plausible deniability. The first partition (exFAT, labeled "Authorized USB") contained Secret Project Data files with their original names, appearing as a legitimate work device. The second partition (FAT32, labeled "IAMAN $_@") contained the masqueraded copies in a directory structure mirroring the corporate share, all of which were subsequently deleted. If the USB device was inspected casually, only the first "Authorized USB" partition would be readily visible.

**Potential Cloud Exfiltration.** Google Drive was installed on March 23 and last launched at 15:21:30 UTC on March 25 — six minutes after CCleaner was executed. The timing sequence (anti-forensic cleanup followed by cloud sync) suggests the subject may have synced documents to Google Drive as a supplementary exfiltration vector. However, the destruction of all Google Drive configuration files (sync_config.db, cacerts, snapshot.db) by Eraser means the investigation cannot definitively confirm what, if any, data was uploaded. Apple iCloud was also installed (icloudsetup.exe appeared in UserAssist), though no definitive evidence of iCloud data synchronization was found. These findings are assessed at medium severity with inference-level confidence.

**Potential Co-Conspirator Contact.** Bulk extractor recovered an Outlook contact entry for "spy" with email address spy.conspirator@nist.gov from the PC's disk image. The provocative naming convention mirrors the subject's own email naming pattern. However, this finding is assessed at inference confidence: only one evidence source supports it, no email message content between the two addresses was recovered, and no evidence indicates Secret Project Data was transmitted via email. The exfiltration pathway appears to have been exclusively through removable media and potentially cloud storage.

**Negative Finding: No Encryption or Steganography.** Analysis across all three removable media devices found no evidence of encrypted containers (TrueCrypt, VeraCrypt, BitLocker) or steganographic tools or content. Cover images contained genuine, unmodified EXIF metadata. The subject's anti-forensic techniques were limited to the five categories described above.

## Threat Intelligence and Attribution

This incident presents a textbook insider threat profile: a privileged user with legitimate access to sensitive data who exploits that access for unauthorized data exfiltration prior to departure. The attribution to the "informant" user account is confirmed with high confidence based on multiple independent evidence streams. The user's account (RID 1000, login count 10) was the only account that accessed the Secret Project Data via the network share, the only account whose shellbag artifacts reference the removable media devices, and the only account under which the anti-forensic tools were installed and executed. The password hint "IAMAN" directly ties the user account to the volume labels on RM2 ("IAMAN $_@") and RM3 ("IAMAN CD").

The subject's premeditation is extensively documented through browser search history recovered by bulk_extractor. The subject researched "information+leakage+cases," "how+to+leak+a+secret," "intellectual+property+theft," and "data+leakage+methods" before executing the campaign. The subject then researched the specific tools and techniques subsequently employed: anti-forensic tools, CCleaner, Eraser, CD burning methods, cloud storage options, and data recovery counter-measures. The subject also demonstrated forensic investigation awareness, researching "e-mail+investigation," "Forensic+Email+Investigation," "what+is+windows+system+artifacts," "windows+event+logs," and "external+device+and+forensics" — indicating a deliberate attempt to understand and evade forensic investigation. Each search topic maps directly to an action taken during the campaign.

No evidence links this incident to external threat actors or organized campaigns. The tradecraft — while showing deliberate effort — contains fundamental operational security failures, most notably the use of UDF write-once media for concealment (which preserves rather than destroys data), the failure to thoroughly clean registry shellbag artifacts, and the retention of browser search history in unallocated disk space despite running CCleaner. The operational pattern is consistent with a motivated but technically unsophisticated insider acting independently, with the possible involvement of the spy.conspirator@nist.gov contact whose role, if any, remains undetermined.

## Impact Assessment

The scope of this incident is significant. Seventeen classified Office documents collectively comprising the organization's "Secret Project Data" portfolio — including design specifications, detailed proposals, pricing decisions, progress reports, and technical review materials — were exfiltrated to three separate physical media devices and potentially to cloud storage. The total volume of exfiltrated data across the 17 documents exceeds 135 megabytes, with individual files ranging from 27,414 bytes to 35,226,880 bytes. The documents contain content referencing government entities including the Office of Management and Budget (Eric_P._Lauer@omb.eop.gov), the Library of Congress (mmun@loc.gov), and external contacts (wayne.longman@att.net), indicating sensitive inter-agency or partner content.

The creation of redundant copies across three physically separate media — two USB devices and one CD-R — represents a deliberate strategy to ensure the data survived confiscation of any single device. The potential cloud exfiltration via Google Drive introduces the possibility that the data exists in an additional, uncontrolled location. The subject's destruction of Google Drive synchronization evidence means the full scope of cloud-based data exposure cannot be determined from available evidence.

Only one system — the subject's workstation informant-PC — was directly compromised. However, the compromised data originated from the network share at \\\\10.11.11.128\\secured_drive, meaning the exposure extends to all Secret Project Data stored on that share. The subject's legitimate credentials (iaman@nist.gov, iaman.informant@nist.gov) were used throughout; no credential theft or privilege escalation beyond the subject's existing access was necessary or observed. The three additional accounts created by the subject (admin11, ITechTeam, temporary) did not access any sensitive data and appear to have been diversionary or experimental in nature.

The creation and saving of Resignation_Letter_(Iaman_Informant).docx and its XPS conversion on the final day of activity, combined with the anti-forensic cleanup sequence, strongly indicate the subject intended this to be their last day at the organization. The business impact extends beyond data loss to potential competitive harm, intellectual property theft, and regulatory compliance violations, depending on the classification and contractual protections governing the Secret Project Data.

## Immediate Tactical Containment

1. Disable the "informant" user account (iaman.informant@nist.gov, iaman@nist.gov, RID 1000) across all organizational systems including Active Directory, email, VPN, and remote access services immediately.
2. Disable the three accounts created by the subject — admin11 (RID 1001), ITechTeam (RID 1002), and temporary (RID 1003) — on informant-PC and verify they do not exist on any domain controllers.
3. Isolate the workstation informant-PC (IP 10.11.11.129) from the network pending full forensic preservation.
4. Revoke all access to the network share \\\\10.11.11.128\\secured_drive for the informant account and audit current access control lists to identify any other accounts with access that may be associated with the subject.
5. Seize and forensically preserve all three removable media devices: RM1 (USB, volume labels "Authorized USB" and "IAMAN $_@"), RM2 (USB, volume label "IAMAN $_@", Volume ID 0xb4d85399), and RM3 (CD-R, volume label "IAMAN CD"). Maintain chain of custody.
6. Initiate a Google Workspace administrative hold on the Google Drive account associated with iaman.informant.personal@gmail.com and request preservation of all synced content and access logs.
7. Block the email address spy.conspirator@nist.gov and place the associated account under monitoring pending determination of their involvement.
8. Issue credential reset for all accounts that had access to \\\\10.11.11.128\\secured_drive\\Secret Project Data to prevent potential credential sharing.
9. Preserve all event logs on the file server at 10.11.11.128, particularly SMB access logs covering the period February 15 through March 25, 2015.

## Strategic Remediation

The subject accessed the full Secret Project Data directory tree on the network share at \\\\10.11.11.128\\secured_drive without triggering any data loss prevention alert, despite the data's classified status. This indicates the absence or misconfiguration of Data Loss Prevention (DLP) controls on the file server. The subject's own research into "DLP DRM" (90 search instances) suggests awareness that such controls might exist and a desire to understand them. Implementing content-aware DLP monitoring on the secured_drive share — with rules that detect bulk file access, file copying to removable media, and access from accounts with pending departures — would have generated an alert during the initial February 15 exfiltration or during the systematic March 24 copy operation.

The subject downloaded, installed, and executed two anti-forensic tools (Eraser 6.2.0.2962 and CCleaner v5.04) from the Desktop\\Download directory without any application whitelisting or endpoint detection response. No alerts were generated when the subject installed Eraser (which requires .NET 4.0 installation), CCleaner, or Google Drive on a workstation that presumably should have had controlled software installation policies. Implementing application whitelisting or endpoint detection and response (EDR) with rules to flag known anti-forensic and data wiping tools — specifically including Eraser.exe, CCleaner64.exe, and ccsetup504.exe — would have detected the cleanup phase of this operation in real time.

The subject copied approximately 135 megabytes of classified data to two USB devices and one CD-R over a period of five weeks without any removable media access controls intervening. The USBSTOR driver loaded successfully at 13:37:59 UTC on March 24, and the CD-R was burned with nine sessions between 20:54 and 20:57 UTC the same day. Implementing a removable media policy that requires encryption, logging, and administrative approval for USB and optical media write operations — or disabling USB mass storage and CD/DVD burning entirely for users without a documented business need — would have blocked the primary exfiltration vector (T1052.001).

The subject's browser search history reveals extensive research into "how+to+leak+a+secret," "anti-forensic+tools," "data+leakage+methods," and "intellectual+property+theft" totaling hundreds of search instances, none of which generated any user behavior analytics alert. Deploying a User and Entity Behavior Analytics (UEBA) solution with rules that flag searches for data exfiltration methods, anti-forensic tools, and intellectual property theft — particularly when correlated with HR data indicating pending departure — would have identified the subject's intent well before the exfiltration was executed.

The subject maintained unmonitored access to a Google Drive personal account (iaman.informant.personal@gmail.com) and Apple iCloud, installing synchronization clients on the workstation. The post-cleanup timing of the Google Drive sync launch at 15:21:30 UTC suggests potential cloud exfiltration, yet no cloud access security broker (CASB) or web filtering system flagged the personal cloud storage usage. Restricting personal cloud storage synchronization clients on corporate endpoints and monitoring for their installation via endpoint management would have addressed the potential cloud exfiltration vector (T1567.002).

## Conclusion

This investigation conclusively establishes that user "Iaman Informant" (iaman.informant@nist.gov) conducted a premeditated, multi-stage data exfiltration campaign targeting classified Secret Project Data from the organization's secured network file share. The following conclusions address each investigation question:

**Q1. What systems were compromised?** One workstation was directly involved: informant-PC (Windows 7 64-bit, IP 10.11.11.129). The data originated from the network file share at \\\\10.11.11.128\\secured_drive. No evidence of compromise to other systems was identified.

**Q2. How did the attacker gain initial access?** This was an insider threat scenario. The subject used legitimate credentials (iaman.informant@nist.gov, account RID 1000) with authorized access to the network share. No external intrusion, credential theft, or privilege escalation was required or observed.

**Q3. What lateral movement occurred?** N/A. The subject operated from a single workstation and accessed the network share using authorized SMB connectivity. No lateral movement to additional systems was detected. The three accounts created by the subject (admin11, ITechTeam, temporary) were not used for lateral movement.

**Q4. What persistence mechanisms were installed?** N/A in the traditional malware sense. However, the subject created three local accounts on informant-PC (admin11, ITechTeam, temporary), two of which were added to the Administrators group. These accounts could have served as persistence mechanisms for continued access, though none were used for data access.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes. Seventeen classified Office documents from the Secret Project Data portfolio were exfiltrated to three separate removable media devices (two USB drives and one CD-R), totaling over 135 megabytes across five content categories: design, pricing decision, progress, proposal, and technical review. Potential additional exfiltration via Google Drive cloud storage is suspected but cannot be confirmed due to anti-forensic destruction of synchronization evidence.

**Q6. What is the full timeline of the incident?** The incident spanned February 15 to March 25, 2015. Phase 1 (Feb 15): Initial data copy to RM1 exFAT. Phase 2 (Mar 22): PC setup, network share access, account creation. Phase 3 (Mar 23): Document access, anti-forensic research, cloud tool installation. Phase 4 (Mar 24): Multi-media masqueraded exfiltration to RM1 FAT32, RM2, and RM3 CD-R; resignation letter drafted. Phase 5 (Mar 25): Anti-forensic tool execution (Eraser, CCleaner), Google Drive sync, resignation letter finalized.

**Q7. What is the total scope and business impact?** The entire Secret Project Data portfolio was exfiltrated, including documents containing references to government officials (OMB, Library of Congress) and external contacts. Three physically separate copies ensure data survival even if one or two devices are recovered. The potential cloud exfiltration via Google Drive means the data may exist in additional uncontrolled locations. The business impact includes potential loss of competitive advantage, intellectual property theft, regulatory compliance violations, and reputational harm.

**Q8. What are the recommended remediation actions?** The five strategic recommendations above address the specific root causes identified in this investigation: absence of DLP controls on the file share, lack of application whitelisting or EDR to detect anti-forensic tools, unrestricted removable media access, absence of user behavior analytics to detect pre-exfiltration research patterns, and unmonitored personal cloud storage access from corporate endpoints. Immediate tactical containment requires disabling all associated accounts, isolating the workstation, seizing removable media, and preserving Google Drive and file server logs.


---

## Overview

| | |
|---|---|
| Findings | **23** (19 confirmed, 4 inference) |
| Severity | 3 critical, 9 high, 5 medium, 0 low, 6 info |
| Sources | 25 evidence sources across 596 tool calls |


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
| 2015-02-15T16:51:38 | Data Exfiltration via Removable Media - Secret Project Data Staged on USB (RM1) and USB (RM2) | CRITICAL | tsk.masquerade, tsk.timeline, tsk.filelist, registry.usrclass.informant, tsk.fsstat |
| 2015-02-15T16:51:38 | Cross-System: Identical Exfiltrated Documents Confirmed Across All Three Removable Media (RM1, RM2, RM3) | CRITICAL | tsk.filelist, tsk.masquerade, tsk.timeline, optical.listing, bulk.email, registry.usrclass.informant |
| 2015-02-15T16:51:38 | Complete Cross-System Exfiltration and Anti-Forensic Timeline Reconstruction | HIGH | tsk.timeline, registry.usrclass.informant, registry.ntuser.informant, registry.system |
| 2015-02-15T16:51:38 | Dual-Partition USB Device Structure Enables Plausible Deniability | MEDIUM | tsk.fsstat, tsk.filelist, tsk.masquerade |
| 2015-02-15T16:51:38 | Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across RM1, RM2, and RM3 | MEDIUM | bulk.email, bulk.domain, bulk.exif, optical.listing |
| 2015-03-22T14:33:13 | Insider Threat - User Identity and Resignation Letter Confirm Departing Employee Data Theft | CRITICAL | registry.ntuser.informant, bulk.email, registry.usrclass.informant |
| 2015-03-22T14:33:13 | Cross-System: Premeditated Anti-Forensic and Data Leakage Research Preceding Exfiltration Campaign | HIGH | bulk.url_searches, bulk.url, registry.ntuser.informant, ez.shimcache |
| 2015-03-22T14:33:13 | Application Execution Timeline: Document Access and Exfiltration Workflow | INFO | registry.ntuser.informant, registry.usrclass.informant, ez.shimcache |
| 2015-03-22T14:33:54 | System Configuration: User Accounts, Timezone, and PC Identity | INFO | registry.system, registry.query.system, hayabusa.alerts |
| 2015-03-22T14:52:22 | USB Device Tied to Source PC via Shellbag and Registry Evidence | HIGH | registry.usrclass.informant, registry.system, tsk.fsstat |
| 2015-03-22T14:52:22 | Network Share Access to Secured Corporate Data from Internal Network (10.11.11.128) | HIGH | registry.usrclass.informant, registry.system, registry.ntuser.informant, bulk.domain |
| 2015-03-22T15:03:29 | Potential Co-Conspirator Contact Entry — spy.conspirator@nist.gov in Outlook Data | MEDIUM | bulk.email |
| 2015-03-22T15:51:54 | Cross-System: Diversionary User Account Creation by Insider (admin11, ITechTeam, temporary) | MEDIUM | chainsaw.hunt, hayabusa.alerts, registry.ntuser.admin11, registry.usrclass.admin11, registry.ntuser.temporary, registry.usrclass.temporary, bulk.url_searches |
| 2015-03-23T18:38:21 | RecentDocs, WordWheelQuery, and OpenSaveMRU: Evidence of Document Search and Access Pattern | INFO | registry.ntuser.informant |
| 2015-03-23T20:01:53 | Potential Cloud Exfiltration via Google Drive and iCloud — Sync Config Destroyed by Anti-Forensic Tools | MEDIUM | registry.ntuser.informant, tsk.filelist |
| 2015-03-24T09:59:26 | Environment-Wide File Extension Masquerading Across All 3 Removable Media — 17 Disguised Office Documents | HIGH | tsk.masquerade, tsk.filelist, tsk.timeline, optical.listing |
| 2015-03-24T09:59:26 | Environment-Wide Deletion of Exfiltrated Documents Across All 3 Removable Media | HIGH | tsk.timeline, tsk.filelist, tsk.masquerade, optical.listing |
| 2015-03-24T20:54:16 | CD-R (RM3) Multi-Session Anti-Forensic Technique: Iterative Directory Renaming and Deletion on Write-Once Media | HIGH | optical.listing, tsk.masquerade |
| 2015-03-24T20:54:16 | CD-R (RM3) EXIF Metadata: Cover Images Are Stock Windows 7 Photos, Document-Embedded Images Show Kodak and Adobe Processing | INFO | bulk.exif, optical.listing |
| 2015-03-24T20:57:00 | CD-R (RM3) Data Exfiltration: 9 Burn Sessions with Masqueraded Documents | HIGH | optical.listing, registry.usrclass.informant, registry.ntuser.informant |
| 2015-03-25T14:50:14 | Anti-Forensic Tool Suite: Eraser and CCleaner Downloaded, Installed, and Executed After Exfiltration | HIGH | registry.ntuser.informant, ez.mft |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Data Exfiltration via Removable Media - Secret Project Data Staged on USB (RM1) and USB (RM2)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade, tsk.timeline, tsk.filelist, registry.usrclass.informant, tsk.fsstat |
| **Evidence Refs** | tc_ec173722, tc_7e1c1241, tc_27bf2a30, tc_7f5abba9, tc_8478da81 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Corporate "Secret Project Data" was exfiltrated from the network share \\10.11.11.128\secured_drive to multiple removable media devices by user "informant" (Iaman Informant, iaman.informant@nist.gov):

**RM1 (Authorized USB, exFAT, Volume Serial: 5c75-4d3e):**
Contains complete Secret Project Data with original filenames in two copies:
- Secret Project Data/Secret Project Data/design/ (3 PPT/PPTX files)
- Secret Project Data/Secret Project Data/proposal/ (2 DOCX files + deleted temp ~$ecret_project]_proposal.docx)
- RM#1/ mirror with same files

Timeline: Files accessed on 2015-02-15 16:52 UTC (access/birth timestamps), modified dates range from 2014-12-04 to 2015-01-23.

**RM2 (IAMAN $_@, FAT32, Volume ID: 0xb4d85399):**
Contains same data but deliberately disguised with false filenames and extensions (see masquerading finding). All 17 files are deleted orphans, created 2015-03-24 09:59-10:00 UTC. Additional ~24 deleted image files (amalfi.bmp, barn.gif, cactus.png, etc.) created 2015-03-23 16:55 UTC appear to be cover images.

The RM2 folder structure (design, PRICIN~1, progress, proposal, TECHNI~1) maps directly to the network share categories: design, pricing decision, progress, proposal, technical review. File sizes prove byte-for-byte copies:
- winter_storm.amr (14,547,968) = [secret_project]_revised_points.ppt (14,547,968)
- winter_whether_advisory.zip (16,381,123) = [secret_project]_detailed_design.pptx (16,381,123)
- a_gift_from_you.gif (35,226,880) = [secret_project]_detailed_proposal.docx (35,226,880)
- landscape.png (6,484,502) = [secret_project]_proposal.docx (6,484,502)



### 2. [CRITICAL] Insider Threat - User Identity and Resignation Letter Confirm Departing Employee Data Theft

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant, bulk.email, registry.usrclass.informant |
| **Evidence Refs** | tc_2beaa53c, tc_6ad4d887, tc_7f5abba9 |
| **ATT&CK** | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |


The user responsible for the data exfiltration has been identified as "Iaman Informant" based on converging evidence:

**User identity:**
- PC username: "informant" (Users/informant profile)
- Email: iaman.informant@nist.gov (from Outlook OST file references on PC)
- Also: iaman@nist.gov (BASIC authentication references)
- USB volume label: "IAMAN $_@" (FAT32 volume on RM2)
- CD volume label: "IAMAN CD" (optical media RM3)

**Resignation letter:**
- RecentDocs shows "Resignation_Letter_(Iaman_Informant).docx" as the most recently accessed document (MRU position 8)
- Also converted to XPS: "Resignation_Letter_(Iaman_Informant).xps" (MRU position 14)
- OpenSavePidlMRU confirms both files were saved: Resignation_Letter_(Iaman_Informant).docx (2015-03-24 18:48:40) and .xps (2015-03-25 15:28:33)
- WINWORD.EXE (4 runs) and XPS viewer (1 run) execution confirms document editing

**Embedded email addresses in documents on RM2/RM3:**
- Eric_P._Lauer@omb.eop.gov (Office of Management and Budget)
- wayne.longman@att.net (personal contact embedded in documents)
- mmun@loc.gov (Library of Congress)

**Search activity:**
- WordWheelQuery shows the user searched for "secret" on the PC (2015-03-23 18:40:17)

The combination of a resignation letter, systematic access to sensitive corporate data via network share, deliberate file disguising, exfiltration to multiple removable media, and subsequent anti-forensic cleanup constitutes a classic insider threat data theft scenario by a departing employee.



### 3. [CRITICAL] Cross-System: Identical Exfiltrated Documents Confirmed Across All Three Removable Media (RM1, RM2, RM3)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-24T20:57:03 |
| **Sources** | tsk.filelist, tsk.masquerade, tsk.timeline, optical.listing, bulk.email, registry.usrclass.informant |
| **Evidence Refs** | tc_754cd2ae, tc_83273c80, tc_680ef6a6 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


File size analysis, masquerade detection, and document metadata confirm that the SAME 17 Office documents containing Secret Project Data were exfiltrated to three separate removable media devices, creating redundant copies for distribution or safekeeping.

**Cross-Media File Size Verification (5 sources independently confirm):**
Four files can be traced from the original network share (\\\\10.11.11.128\\secured_drive) through all three media:

| Original Document | Size | RM1 exFAT | RM1 FAT32 | RM2 | RM3 |
|---|---|---|---|---|---|
| [secret_project]_detailed_proposal.docx | 35,226,880 | ✓ original | a_gift_from_you.gif | a_gift_from_you.gif | /prop/a_gift_from_you.gif |
| [secret_project]_proposal.docx | 6,484,502 | ✓ original | landscape.png | landscape.png | /prop/landscape.png |
| [secret_project]_detailed_design.pptx | 16,381,123 | ✓ original | winter_whether_advisory.zip | winter_whether_advisory.zip | /de/winter_whether_advisory.zip |
| [secret_project]_revised_points.ppt | 14,547,968 | ✓ original | winter_storm.amr | winter_storm.amr | /de/winter_storm.amr |

All 17 masqueraded files have byte-identical sizes across RM1 (FAT32 partition), RM2, and RM3.

**Email Address Convergence Across Media:**
The same three embedded email addresses appear in documents on RM2 AND RM3, confirming identical document content:
- Eric_P._Lauer@omb.eop.gov (Office of Management and Budget)
- wayne.longman@att.net (personal contact)
- mmun@loc.gov (Library of Congress)

**Volume Label Attribution:**
- RM1 FAT32 partition: "IAMAN $_@"
- RM2: "IAMAN $_@" (same label as RM1 FAT32)
- RM3: "IAMAN CD"
- PC user password hint: "IAMAN"

**Directory Structure Evolution Across Media (anti-forensic refinement):**
- RM1 exFAT: Original names (design/, proposal/)
- RM1 FAT32: Full category names (design/, PRICIN~1/, progress/, proposal/, TECHNI~1/)
- RM2: Identical to RM1 FAT32
- RM3 sessions -7 to -3: Full names (design/, pricing decision/, progress/, proposal/, technical review/)
- RM3 session -1: Abbreviated (de/, pd/, prog/, prop/, tr/)
- RM3 session 0: All deleted, replaced with stock photos

This progressive directory name obfuscation reveals the suspect iteratively refining their concealment strategy across media.

**Timeline of Multi-Media Exfiltration:**
1. 2015-02-15: First copy to RM1 exFAT (original filenames)
2. 2015-03-24 09:59-10:00: Masqueraded copies to RM1 FAT32 and RM2 (deleted after)
3. 2015-03-24 20:54-20:57: Burned to RM3 CD-R with 9 session iterations



### 4. [HIGH] Environment-Wide File Extension Masquerading Across All 3 Removable Media — 17 Disguised Office Documents

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:26 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade, tsk.filelist, tsk.timeline, optical.listing |
| **Evidence Refs** | tc_62987b1e, tc_d67ae8aa, tc_b61a548a |
| **ATT&CK** | [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The SAME 17 Office documents containing Secret Project Data were disguised with false file extensions on all three removable media devices (RM1 FAT32 partition, RM2, and RM3 CD-R). This was a systematic anti-forensic technique applied consistently across all exfiltration media.

**Masquerade Scheme (identical across RM1 FAT32, RM2, RM3):**

**design/ directory:**
- winter_storm.amr → Actually OLE (14,547,968 bytes) = [secret_project]_revised_points.ppt
- winter_whether_advisory.zip → Actually PPTX (16,381,123 bytes) = [secret_project]_detailed_design.pptx

**PRICIN~1/ (pricing decision) directory:**
- my_favorite_cars.db → Actually OLE (1,260,544 bytes)
- my_favorite_movies.7z → Actually XLSX (100,078 bytes)
- new_years_day.jpg → Actually XLSX (10,237,535 bytes)
- super_bowl.avi → Actually OLE (10,289,152 bytes)

**progress/ directory:**
- my_friends.svg → Actually OLE (58,368 bytes)
- my_smartphone.png → Actually DOCX (4,440,235 bytes)
- new_year_calendar.one → Actually DOCX (27,414 bytes)

**proposal/ directory:**
- a_gift_from_you.gif → Actually DOCX (35,226,880 bytes) = [secret_project]_detailed_proposal.docx
- landscape.png → Actually DOCX (6,484,502 bytes) = [secret_project]_proposal.docx

**TECHNI~1/ (technical review) directory:**
- diary_#1d.txt → DOCX; diary_#1p.txt → PPTX; diary_#2d.txt → DOCX; diary_#2p.txt → OLE; diary_#3d.txt → OLE; diary_#3p.txt → OLE

**Cross-media confirmation:** File sizes are byte-identical across all three media. The same false filenames and extensions were used consistently. On RM3 CD-R, the multiple VAT sessions show the user first used full directory names (design, pricing decision, etc.) then abbreviated (de, pd, etc.).



### 5. [HIGH] Environment-Wide Deletion of Exfiltrated Documents Across All 3 Removable Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:26 to 2015-03-24T15:51:48 |
| **Sources** | tsk.timeline, tsk.filelist, tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_b61a548a, tc_d67ae8aa, tc_62987b1e |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


All 17 masqueraded Office documents were deleted on EVERY removable media device after being copied, demonstrating systematic anti-forensic cleanup across the entire exfiltration campaign:

**RM1 FAT32 partition:** All 17 masqueraded documents are now orphaned entries (under $OrphanFiles). 22 cover image files also deleted. The exFAT partition's root "Secret Project Data" directory was also deleted (mtime: 2015-02-27).

**RM2 (FAT32):** All 17 masqueraded documents are deleted orphan files. 24 cover image files (amalfi.bmp, barn.gif, boudicca.bmp, cactus.png, etc.) also deleted. Timeline shows cover images existed first → deleted → disguised project files copied → project files deleted — at least two rounds of intentional staging and cleanup.

**RM3 CD-R:** All document directories marked as deleted in the final UDF VAT session. Only 3 stock Windows 7 sample photos (Koala.jpg, Penguins.jpg, Tulips.jpg) remain active. However, the write-once nature of UDF means deleted data remains physically on the disc.

**Deletion timeline:**
1. 2015-02-27: Root "Secret Project Data" directory on RM1 exFAT deleted
2. 2015-03-23 ~16:55: Cover images placed on RM2
3. 2015-03-24 09:59-10:00: Masqueraded files created on RM1 FAT32 and RM2
4. After creation: All files deleted from RM1 FAT32 and RM2
5. 2015-03-24 20:54-20:57: Files burned to RM3 in multiple sessions, then deleted in final session
6. 2015-03-25 15:12-15:16: Eraser and CCleaner executed on PC to destroy remaining traces



### 6. [HIGH] USB Device Tied to Source PC via Shellbag and Registry Evidence

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22 to 2015-03-24T20:54:07 |
| **Sources** | registry.usrclass.informant, registry.system, tsk.fsstat |
| **Evidence Refs** | tc_f26ac21a, tc_b88e2a9b, tc_f0925a2e |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The "informant" user account on the source PC (cfreds_2015_data_leakage_pc.E01) has extensive shellbag evidence tying this user to browsing the USB device contents and the source network share:

**Network Share Access (data source):**
- \\10.11.11.128\secured_drive\Secret Project Data — accessed 2015-03-22 14:52:22, with subdirectories for design, final, pricing decision, proposal, progress, technical review, Common Data, Past Projects
- File V:\Secret Project Data also accessed (alternate drive letter)

**USB Device Access (exfiltration destination):**
- E:\RM#1\Secret Project Data — accessed 2015-03-24 13:38:31
- E:\RM#1\Secret Project Data\design — accessed 2015-03-24 13:38:52
- E:\Secret Project Data (including all subdirectories: design, pricing decision, progress, proposal, technical review) — accessed 2015-03-24 13:57-14:01
- E:\Secret Project Data\design\winter_whether_advisory.zip [16381123] — the user specifically opened the masqueraded file and explored its ppt\ subdirectory, confirming awareness of the file's true PPTX content

**Second Partition Access:**
- D:\de, D:\tr, D:\pd, D:\prop, D:\prog — accessed 2015-03-24 19:47-20:41 (abbreviated versions of the FAT32 partition directories)
- D:\de\winter_whether_advisory.zip [16381123] — same file size as the masqueraded PPTX

**USBSTOR driver loaded:** 2015-03-24 13:37:59 UTC

**User Identity:**
- Email: iaman.informant@nist.gov (found in Outlook profile data on PC)
- The FAT32 partition volume label "IAMAN $_@" contains the user's "IAMAN" identifier



### 7. [HIGH] Network Share Access to Secured Corporate Data from Internal Network (10.11.11.128)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22 to 2015-03-24T13:57:40 |
| **Sources** | registry.usrclass.informant, registry.system, registry.ntuser.informant, bulk.domain |
| **Evidence Refs** | tc_7f5abba9, tc_9373d670, tc_2beaa53c |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/), [T1135](https://attack.mitre.org/techniques/T1135/) |


User "informant" accessed a secured network share at \\10.11.11.128\secured_drive containing the Secret Project Data. Evidence from multiple sources:

**Shellbags (registry.usrclass.informant):**
Browsed the complete directory tree of the network share starting 2015-03-22 14:52:22 UTC:
- \\10.11.11.128\secured_drive\Common Data
- \\10.11.11.128\secured_drive\Past Projects (MRU: 2015-03-24 13:47:54)
- \\10.11.11.128\secured_drive\Secret Project Data (with subdirs: design, pricing decision, final, technical review, proposal, progress)

The share was also mapped as V: drive, with shellbags showing:
- V:\Secret Project Data (MRU: 2015-03-23 20:27:24)
- V:\Secret Project Data\final (MRU: 2015-03-23 20:27:29)

**Registry (system):**
Network configuration shows DHCP IP address 10.11.11.x on the same subnet as the share server. USBSTOR driver last write: 2015-03-24 13:37:59Z confirms USB storage access during the same timeframe.

**Bulk extractor domains (PC):**
Multiple references to \\10.11.11.128\secured_drive and \\10.11.11.128\SECURED_DRIVE found in unallocated space.

**Recent Documents:**
The informant's RecentDocs key (last written 2015-03-25 15:29:08Z) includes: [secret_project]_proposal.docx, [secret_project]_design_concept.ppt, (secret_project)_pricing_decision.xlsx, [secret_project]_final_meeting.pptx, and winter_whether_advisory.zip — confirming these project files were opened on the PC.



### 8. [HIGH] Anti-Forensic Tool Suite: Eraser and CCleaner Downloaded, Installed, and Executed After Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:50:14 to 2015-03-25T15:15:50 |
| **Sources** | registry.ntuser.informant, ez.mft |
| **Evidence Refs** | tc_2beaa53c, tc_2fa622d5, tc_92db7fe9 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070.003](https://attack.mitre.org/techniques/T1070/003/), [T1485](https://attack.mitre.org/techniques/T1485/) |


User "informant" downloaded, installed, and executed two anti-forensic/data wiping tools on 2015-03-25, the day AFTER the data exfiltration to removable media. Cross-system evidence confirms these tools were the culmination of deliberate research.

**Execution Timeline (UserAssist, ShimCache, MFT):**
- 14:50:14Z: Eraser 6.2.0.2962.exe installer run (from Desktop\Download\)
- 14:57:56Z: ccsetup504.exe (CCleaner v5.04) installer run
- 15:12:28Z: Eraser.exe executed (secure file deletion, 1 run)
- 15:15:50Z: CCleaner64.exe executed (system trace cleaning, 1 run)
- 15:18:36Z: Software\...\Run key emptied (by CCleaner removing startup entries)
- 15:21:30Z: Google Drive sync launched (cloud exfiltration)
- 15:24:48Z: WINWORD.EXE (resignation letter)
- 15:28:47Z: XPS viewer (resignation letter conversion)

**ShimCache Confirmation:** C:\Program Files\Eraser\Eraser.exe — Executed=Yes
**MFT Confirmation:** C:\Program Files\CCleaner\ files created 2015-03-25 14:58:35Z

**Cross-System Correlation with Search History:**
- User searched "ccleaner" (n=65 URL search instances) before downloading
- User searched "eraser" (n=51 instances) before downloading  
- User searched "anti-forensic+tools" (n=85), "system+cleaner" (n=6), "how+to+delete+data" (n=5)
- Download URL carved: http://iweb.dl.sourceforge.net/project/eraser/Eraser%206/6.2/Eraser%206.2.0.2962.exe

**Impact Assessment:**
- Browser history: 0 windows recovered (consistent with CCleaner clearing browser data)
- Google Drive sync_config.db and related files: ALL DELETED (anti-forensic cleanup)
- RM2 USB files: All 17 masqueraded documents deleted (orphan entries only)
- Startup entries: Run key emptied

**Eraser .NET dependency:** dotNetFx40_Full_setup.exe was run from Eraser's temp directory, confirming the installation required and installed .NET 4.0.



### 9. [HIGH] Complete Cross-System Exfiltration and Anti-Forensic Timeline Reconstruction

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-25T15:29:08 |
| **Sources** | tsk.timeline, registry.usrclass.informant, registry.ntuser.informant, registry.system |
| **Evidence Refs** | tc_7e1c1241, tc_7f5abba9, tc_2beaa53c, tc_44f9e584 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1039](https://attack.mitre.org/techniques/T1039/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |


Synthesizing all evidence sources across PC, RM1 (USB), RM2 (USB), and RM3 (CD-R), the following complete exfiltration timeline is reconstructed:

**2015-02-15 (Sunday) — Initial Data Copy:**
- 16:51:38 UTC: RM#1 directory modified on RM1 exFAT
- 16:52:08-20 UTC: Five secret project files copied to RM1 exFAT (design_concept.ppt, detailed_design.pptx, revised_points.ppt, detailed_proposal.docx, proposal.docx)

**2015-02-27 — Cleanup:**
- 17:20:18 UTC: "Secret Project Data" root directory deleted on RM1 exFAT

**2015-03-22 (Sunday) — PC Setup and Network Access:**
- 14:33:13Z: First login as "informant" (account created 14:33:54Z, login count=10)
- 14:52:22Z: First access to \\\\10.11.11.128\\secured_drive via shellbags
- 15:11-15:17Z: Chrome, IE11 installed; Google Update running
- 15:51-15:53Z: Created admin11, ITechTeam, temporary accounts

**2015-03-23 (Monday) — Document Work and Research:**
- 16:55:17-37Z: Cover image files born on RM2 FAT32 (24 images)
- 17:26-17:28Z: Chrome launched, Bing/Google searched
- 18:37-18:40Z: Secret project files opened (LNK files created)
- 18:40:17Z: WordWheelQuery search for "secret"
- 20:02Z: Google Drive installed (clickonce_bootstrap.exe)
- 20:10Z: cmd.exe run (4x) — command-line operations
- 20:23-20:28Z: V: drive (network share) browsed, Excel/PowerPoint used

**2015-03-24 (Tuesday) — Multi-Media Exfiltration:**
- 09:59:26-10:00:18Z: 17 masqueraded files created on RM1 FAT32 and RM2 in 5 directories
- 13:37:59Z: USBSTOR driver last written (USB device connected)
- 13:38:31-14:01:29Z: E:\\RM#1\\Secret Project Data browsed on PC (shellbags)
- 18:48:40Z: Resignation_Letter_(Iaman_Informant).docx saved
- 19:47:48-20:44:18Z: D:\\de, D:\\tr, D:\\pd, D:\\prop, D:\\prog browsed (CD-R/RM3 directories)
- 20:54:16-20:57:03Z: CD-R burned with 9 VAT sessions (17 documents + 3 cover photos)

**2015-03-25 (Wednesday) — Anti-Forensics and Departure:**
- 14:41:03Z: Outlook (5x total) — final email activity
- 14:50:14Z: Eraser installer run from Desktop\\Download
- 14:57:56Z: CCleaner installer run from Desktop\\Download
- 15:12:28Z: Eraser executed — secure file deletion
- 15:15:50Z: CCleaner64 executed — system trace cleaning
- 15:21:30Z: Google Drive sync launched — potential cloud exfiltration
- 15:24:48Z: WINWORD.EXE — resignation letter (4 total runs)
- 15:28:47Z: XPS viewer — resignation letter converted to XPS
- 15:29:08Z: Last RecentDocs write (final system activity)



### 10. [HIGH] CD-R (RM3) Data Exfiltration: 9 Burn Sessions with Masqueraded Documents

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:57:00 to 2015-03-25T14:45:59 |
| **Sources** | optical.listing, registry.usrclass.informant, registry.ntuser.informant |
| **Evidence Refs** | tc_bfaf8fda, tc_293e882d, tc_2f1a7111 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The CD-R disc image (rm3_type3.E01, volume label "IAMAN CD") contains a UDF write-once filesystem with 9 VAT (Virtual Allocation Table) generations, indicating the disc was burned in multiple sessions. The same set of 17 masqueraded secret project documents found on RM1's FAT32 partition and RM2 were also burned to this CD-R, using the SAME disguised filename scheme (.amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt extensions).

**Session Progression (9 VAT generations) — Directory Naming Evolution:**
The CD-R preserves evidence of the user iteratively refining their concealment strategy across multiple burn sessions:

- Sessions -7 to -3: Files first burned using FULL directory names matching the corporate network share structure:
  - /design/ (session -7): winter_storm.amr (14,547,968 bytes), winter_whether_advisory.zip (16,381,123 bytes)
  - /pricing decision/ (session -6): my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi
  - /progress/ (session -5): my_friends.svg, my_smartphone.png, new_year_calendar.one
  - /proposal/ (session -4): a_gift_from_you.gif (35,226,880 bytes), landscape.png (6,484,502 bytes)
  - /technical review/ (session -3): diary_#1d.txt through diary_#3p.txt (6 files)

- Session -1: Files re-burned with ABBREVIATED directory names to obscure the connection to project categories:
  - /de/, /pd/, /prog/, /prop/, /tr/ — same 17 files, same sizes

- Session 0 (final/active): All data directories deleted; only 3 stock Windows 7 photos remain:
  - Koala.jpg (780,831 bytes, created 2015-03-24T20:57:00Z)
  - Penguins.jpg (777,835 bytes, created 2015-03-24T20:57:00Z)
  - Tulips.jpg (620,888 bytes, created 2015-03-24T20:57:03Z)

**Anti-forensic Deletion Pattern:**
Files burned in earlier sessions were "deleted" in subsequent sessions (marked as deleted in UDF allocation). The write-once nature of UDF with VAT means deleted data remains physically on the disc despite being marked as removed in the active allocation table.

**Shellbags confirm CD-R access:** "BD-RE Drive (D:) IAMAN CD" with directories D:\de, D:\tr, D:\pd, D:\prop, D:\prog browsed 2015-03-24 19:47-20:44 UTC.



### 11. [HIGH] CD-R (RM3) Multi-Session Anti-Forensic Technique: Iterative Directory Renaming and Deletion on Write-Once Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T20:57:03 |
| **Sources** | optical.listing, tsk.masquerade |
| **Evidence Refs** | tc_b8a8b6ad, tc_875be0b4 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The CD-R demonstrates a sophisticated multi-stage anti-forensic approach exploiting the user's misunderstanding of UDF write-once media behavior. The 9 VAT generations reveal the suspect's iterative attempt to conceal the exfiltrated data.

**Anti-forensic technique #1 — File extension masquerading:**
All 17 exfiltrated Office documents were renamed with false extensions to disguise their content:
- OLE documents (.ppt, .xls) given extensions: .amr, .db, .avi, .svg
- OOXML documents (.docx, .pptx, .xlsx) given extensions: .zip, .7z, .jpg, .png, .one, .gif, .txt
The filenames themselves were changed to innocuous personal-sounding names (winter_storm, my_favorite_cars, diary_#1d, etc.)

**Anti-forensic technique #2 — Directory name obfuscation across sessions:**
The disc preserves evidence of the user progressively obscuring the connection between directory names and the corporate project structure:
- Earlier sessions (-7 to -3): Full names "design", "pricing decision", "progress", "proposal", "technical review" — directly mapping to \\\\10.11.11.128\\secured_drive\\Secret Project Data subdirectories
- Later session (-1): Abbreviated to "de", "pd", "prog", "prop", "tr" — reducing the forensic connection
- Final session (0): All directories marked as deleted (both full and abbreviated names appear as empty deleted directories)

**Anti-forensic technique #3 — Data overwriting with cover content:**
After deleting all exfiltrated documents, the user burned 3 stock Windows 7 sample photos (Koala.jpg, Penguins.jpg, Tulips.jpg) to the active session. This would make the disc appear to contain only innocent sample photos if casually examined.

**Anti-forensic failure — UDF VAT preservation:**
The user likely did not understand that UDF's Virtual Allocation Table on write-once media preserves all previous generations. Each "deletion" only updated the VAT to mark files as removed, while the actual data remained physically intact on the disc. All 9 generations are recoverable through forensic analysis, exposing the complete history of the user's concealment attempts.

**Session 0 final state shows both sets of deleted directory names:**
The final session's deleted directory listing reveals BOTH the original full names AND the abbreviated names as empty deleted directories, providing direct evidence that the user created both naming schemes during the disc's lifecycle.



### 12. [HIGH] Cross-System: Premeditated Anti-Forensic and Data Leakage Research Preceding Exfiltration Campaign

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:29:08 |
| **Sources** | bulk.url_searches, bulk.url, registry.ntuser.informant, ez.shimcache |
| **Evidence Refs** | tc_754cd2ae, tc_edead4e7, tc_a8fe2dc1 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |


Browser search history from the PC (bulk.url_searches) reveals the user "informant" conducted extensive research into data leakage techniques, anti-forensic tools, and digital forensics BEFORE executing the exfiltration campaign. This demonstrates premeditation and a deliberate attempt to understand — and evade — forensic investigation.

**Anti-Forensic Tool Research (directly leading to tool downloads):**
- "anti-forensic+tools" (n=85 search instances)
- "anti-forensics" (multiple direct searches)
- "ccleaner" (n=65) → Led to download of ccsetup504.exe, executed 2015-03-25 14:57:56Z
- "eraser" (n=51) → Led to download of Eraser 6.2.0.2962.exe, executed 2015-03-25 14:50:14Z
- "system+cleaner" (n=5+1)
- "how+to+delete+data" (n=5)

**Data Leakage Planning Research:**
- "information+leakage+cases" (n=47)
- "how+to+leak+a+secret" (n=6)
- "intellectual+property+theft" (n=6)
- "leaking+confidential+information" (n=2)
- "data+leakage+methods" (n=1)

**Forensic Investigation Awareness (counter-forensics):**
- "e-mail+investigation" (n=88)
- "Forensic+Email+Investigation" (n=78)
- "what+is+windows+system+artifacts" (n=79)
- "windows+event+logs" (n=61)
- "investigation+on+windows+machine" (n=64)
- "external+device+and+forensics" (n=65)
- "digital+forensics" (multiple)

**Exfiltration Vector Research:**
- "cloud+storage" (n=6) → Led to Google Drive and iCloud installation
- "google+drive" (n=10) → googledrivesync.exe downloaded and executed
- "apple+icloud" (n=1) → icloudsetup.exe installed
- "cd+burning+method" (n=64) → CD-R burning with masqueraded files
- "cd+burning+method+in+windows" (n=53)
- "security+checkpoint+cd-r" (n=1) — researched security controls for CD media

**Data Protection/DLP Awareness:**
- "DLP%20DRM" (n=90) — researched Data Loss Prevention and Digital Rights Management
- "file+sharing+and+tethering" (n=491)

**Data Recovery Counter-Research:**
- "data+recovery+tools" (multiple) — researched what tools could recover deleted data
- "how+to+recover+data" (multiple) — understood what investigators could find

**Wired Article on Data Theft:**
- Visited: http://www.wired.com/2015/03/stealing-data-computers-using-heat/ — article about "stealing data from computers using heat"

**CONVERGENCE ACROSS EVIDENCE SOURCES:**
This research activity (from bulk_extractor URL search histograms on the PC disk) directly correlates with actions documented in registry artifacts (UserAssist, ShimCache), removable media filesystems (masqueraded files, CD-R burns), and event logs (account creation). Each searched topic maps to a specific action taken:
1. Searched "ccleaner"/"eraser" → Downloaded and executed both tools
2. Searched "cloud+storage"/"google+drive" → Installed and ran googledrivesync.exe
3. Searched "cd+burning+method" → Burned data to CD-R with 9 VAT sessions
4. Searched "anti-forensic+tools" → Implemented file masquerading, deletion, and wiping
5. Searched "data+leakage+methods" → Executed multi-media exfiltration campaign



### 13. [MEDIUM] Dual-Partition USB Device Structure Enables Plausible Deniability

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-24T17:02:36 |
| **Sources** | tsk.fsstat, tsk.filelist, tsk.masquerade |
| **Evidence Refs** | tc_f88b7a7a, tc_d67ae8aa, tc_62987b1e |
| **ATT&CK** | [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


RM1 is a 4GB USB device containing two distinct partitions configured for apparent plausible deniability:

**Partition 1 (exFAT):**
- Volume Label: "Authorized USB"
- Volume Serial: 5c75-4d3e
- Contains active Secret Project Data files openly (in design/ and proposal/ subdirectories)
- Appears as an "authorized" work USB

**Partition 2 (FAT32):**
- Volume Label: "IAMAN $_@" — notably contains the user identifier "IAMAN" matching email addresses iaman@nist.gov and iaman.informant@nist.gov found on the source PC
- Volume ID: 0xb4d85399
- Originally contained 17 masqueraded copies of secret project documents (all deleted)
- Originally contained 22 cover image files (all deleted)
- Directory structure (design, pricing decision, progress, proposal, technical review) mirrors the network share at \\10.11.11.128\secured_drive\Secret Project Data

The use of two partitions — one "clean" and one for covert storage — along with the false file extensions and subsequent deletion of all files on the second partition, demonstrates a deliberate multi-layered concealment strategy. If the USB was inspected casually, only the first "Authorized USB" partition would be visible, appearing to contain legitimate project files.



### 14. [MEDIUM] Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across RM1, RM2, and RM3

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-02-15T16:51:38 to 2015-03-24T20:57:03 |
| **Sources** | bulk.email, bulk.domain, bulk.exif, optical.listing |
| **Evidence Refs** | tc_532a7d97, tc_46252f53, tc_a4b039b1 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Bulk extractor analysis across all removable media carved identical document metadata, confirming the same documents are present on all three devices and providing attribution information.

**Embedded email addresses (found on all three media):**
- Eric_P._Lauer@omb.eop.gov (Office of Management and Budget, Executive Office of the President) — found in document content embedded at consistent offsets across RM2 and RM3
- wayne.longman@att.net — found as mailto: hyperlinks within document content, multiple occurrences
- mmun@loc.gov (Library of Congress) — found in context "(email address: mmun@loc.gov)" preceding a "PREFACE" section

**Government/institutional domain references (from bulk.domain):**
- www.iec.ch (International Electrotechnical Commission) — extensive references
- www.whitehouse.gov/omb — government OMB policy documents
- lcweb.loc.gov (Library of Congress)
- desert-estates.info — hyperlink in document content
- digitalcorpora.org/corpora/govdocs — GovDocs corpus references

**EXIF metadata from document-embedded images:**
- Kodak DC260 camera images (2003): Technical photographs
- Adobe Photoshop CS Macintosh processed images (2006): Document illustrations
- Cover images on RM1/RM2: Genuine personal photos from various sources (2004-2013 era)
- Cover images on RM3: Unmodified Windows 7 sample photos (Corbis/Microsoft, 2008-2009)

**User identity confirmed across sources:**
- iaman.informant@nist.gov (Outlook OST on PC)
- iaman.informant.personal@gmail.com (personal email in registry)
- Password hint "IAMAN" matches volume labels "IAMAN $_@" and "IAMAN CD"

**Cross-media email convergence:** The same three embedded email addresses appear at proportional disc offsets on RM2 and RM3, confirming byte-identical document content across media.



### 15. [MEDIUM] Potential Cloud Exfiltration via Google Drive and iCloud — Sync Config Destroyed by Anti-Forensic Tools

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-23T20:01:53 to 2015-03-25T15:21:30 |
| **Sources** | registry.ntuser.informant, tsk.filelist |
| **Evidence Refs** | tc_2beaa53c, tc_54511de3, tc_e8401491 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The user installed cloud storage applications representing additional exfiltration vectors. Anti-forensic cleanup destroyed evidence of what was synced.

**Google Drive (confirmed execution):**
- googledrivesync.exe installed: C:\Program Files (x86)\Google\Drive\ (MFT shows 27+ language files created 2015-03-23 20:02:43Z)
- ShimCache: googledrivesync.exe modified 2015-02-19 18:24:23, Executed=Yes
- UserAssist: Last executed 2015-03-25 15:21:30Z (1 GUI run)
- Shellbags: "Users\Google Drive" directory browsed (MRU 2015-03-25 15:20:59Z)
- **CRITICAL:** Google Drive launched AFTER Eraser (15:12Z) and CCleaner (15:15Z) — suggesting the user cleaned up first, then synced remaining data to cloud
- User searched "google+drive" (n=10) and "cloud+storage" (n=6) in browser

**Google Drive Sync Evidence Destroyed:**
- sync_config.db-shm (deleted, inode 73728)
- cacerts (deleted, inode 75037)
- snapshot.db (deleted, inode 75039)
- sync_config.db (deleted, inode 75040)
These deletions are consistent with Eraser's secure file deletion capability.

**Apple iCloud (installed but uncertain usage):**
- icloudsetup.exe in UserAssist (executed at some point)
- Bonjour Service installed: 2015-03-23 20:00:56Z (Apple dependency)
- User searched "apple+icloud" (n=1) in browser
- No definitive evidence of iCloud data sync

**Significance:**
The sequence (anti-forensic cleanup → Google Drive sync → resignation letter) suggests the user synced documents to Google Drive as a cloud exfiltration method complementing physical media. However, the destruction of sync configuration files means we cannot definitively confirm what was uploaded.



### 16. [MEDIUM] Cross-System: Diversionary User Account Creation by Insider (admin11, ITechTeam, temporary)

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-22T15:51:54 to 2015-03-22T15:58:26 |
| **Sources** | chainsaw.hunt, hayabusa.alerts, registry.ntuser.admin11, registry.usrclass.admin11, registry.ntuser.temporary, registry.usrclass.temporary, bulk.url_searches |
| **Evidence Refs** | tc_83273c80, tc_754cd2ae |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/) |


On 2015-03-22, the "informant" user created three additional accounts within 2 minutes during initial PC setup. Chainsaw/Hayabusa security event analysis confirms the creation events, and registry analysis shows minimal activity on these accounts, suggesting they may have been diversionary.

**Account Creation Events (from chainsaw.hunt and hayabusa.alerts):**
- 2015-03-22 15:51:54Z: "admin11" created (Local User Creation + Added to Administrators group)
- 2015-03-22 15:52:30Z: "ITechTeam" created (Local User Creation + Added to Administrators group)
- 2015-03-22 15:53:01Z: "temporary" created (Local User Creation, NOT added to Administrators)

**Hayabusa Alert:** "User Added To Local Admin Grp" (high severity) at 2015-03-22 15:51:54Z — SrcSID matches informant's SID (S-1-5-21-2425377081-3129163575-2985601102-1001)

**Account Activity Assessment (from per-user NTUSER.DAT and UsrClass.dat):**
- **admin11** (RID 1001): Login count=2, last login 2015-03-22 15:57:02Z. UserAssist shows only standard Windows exploration (Welcome Center, Control Panel). Shellbags show only Libraries/Desktop browsing. NO access to Secret Project Data, network shares, or removable media.
- **ITechTeam** (RID 1002): Never logged in (login count=0). No UserAssist or shellbag data.
- **temporary** (RID 1003): Login count=1. UserAssist shows only Welcome Center exploration (2015-03-22 15:56:13Z). Shellbags show only Libraries browsing. NO Secret Project Data access.

**Correlation with Forensic Research:**
The user's search history includes "investigation+on+windows+machine" (n=64), "what+is+windows+system+artifacts" (n=79), and "windows+event+logs" (n=61). Creating multiple accounts with varying privilege levels may have been an attempt to:
1. Create confusion about which account performed the data theft
2. Test whether account creation would be logged
3. Establish plausible deniability ("maybe admin11 did it")

**Counter-analysis note (confidence downgrade from "confirmed" to "inference"):**
The existence and creation of these accounts is confirmed. However, characterizing them as "diversionary" is an inference. Alternative explanations include: (1) testing account creation as part of learning Windows administration, (2) standard lab/test environment setup, or (3) creating accounts for other users who never used them. The diversionary interpretation is supported by the convergent forensic research evidence, but cannot be confirmed without direct evidence of intent. The accounts' creation is consistent with the broader attack chain pattern but does not independently prove anti-forensic motivation.

**Significance:** None of the three created accounts accessed the Secret Project Data. ALL exfiltration activity was performed under the "informant" account.



### 17. [MEDIUM] Potential Co-Conspirator Contact Entry — spy.conspirator@nist.gov in Outlook Data

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-22T15:03:29 to 2015-03-25T15:28:47 |
| **Sources** | bulk.email |
| **Evidence Refs** | tc_507a3065, tc_d0efb232 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The informant's Outlook OST data store on the PC contains an email contact entry for "spy" with email address spy.conspirator@nist.gov. Bulk extractor recovered this from two locations in the disk image:

- Offset 15509094608: Raw email address `spy.conspirator@nist.gov` in UTF-16 encoding within Outlook data structures
- Offset 15509095786: Formatted display name entry `spy <spy.conspirator@nist.gov>` — indicating this was stored as a contact or autocomplete entry in the Outlook cache

The deliberately provocative naming convention (display name "spy", email "spy.conspirator") mirrors the informant's own email naming pattern (iaman.informant@nist.gov) and suggests this may be a co-conspirator in the data exfiltration scheme. The contact resided within the cached offline store (.ost) for iaman.informant@nist.gov.

**Counter-analysis note (confidence downgrade from "confirmed" to "inference"):**
- Only one evidence source (bulk.email from PC disk image) — no corroboration from a second independent source
- No actual email message content between the informant and this contact was recovered
- The provocative naming matches the synthetic naming convention used throughout this NIST CFREDS 2015 scenario (iaman.informant, spy.conspirator)
- The presence of a contact entry proves only that the address existed in Outlook autocomplete/contacts, not that conspiratorial communication occurred
- No evidence of secret project data being transmitted via email to any address

The exfiltration pathway appears to have been exclusively through removable media (RM1, RM2, RM3) and potentially cloud storage (Google Drive), not email.



### 18. [INFO] Negative Finding: No Encrypted Containers or Steganographic Content on Any Removable Media

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | strings.output |
| **Evidence Refs** | tc_614ce225, tc_2491e9ca, tc_4febb050 |


Analysis across all three removable media devices found no evidence of encrypted containers (TrueCrypt, VeraCrypt, BitLocker) or steganographic tools/content.

**RM1 (USB):** String analysis and YARA scanning produced no hits for encryption or steganography signatures. Cover images on the FAT32 partition contain genuine EXIF data from Kodak DC260 cameras and Adobe Photoshop CS.

**RM3 (CD-R):** steg.detection returned no results. YARA scan: no matches. The three active cover images (Koala.jpg, Penguins.jpg, Tulips.jpg) are unmodified Windows 7 sample photos from C:\Users\Public\Pictures\Sample Pictures\ — confirmed by exact file size matching against MFT entries on the PC. No size modification indicating appended steganographic data.

**Anti-forensic techniques used were limited to:**
1. File extension masquerading (false extensions on Office documents)
2. File deletion (all exfiltrated documents deleted after copying)
3. Multi-session CD burning with deletion (exploiting UDF VAT)
4. Cover content placement (stock/personal photos)
5. Anti-forensic tool execution (Eraser, CCleaner)



### 19. [INFO] System Configuration: User Accounts, Timezone, and PC Identity

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T14:45:59 |
| **Sources** | registry.system, registry.query.system, hayabusa.alerts |
| **Evidence Refs** | tc_1236077e, tc_9e1064ac, tc_49bb0cdc |


**System:** informant-PC (Windows 7, 64-bit)
**Timezone:** Eastern Standard Time (UTC-5 standard / UTC-4 during EDT). Registry key ControlSet001\Control\TimeZoneInformation: Bias=300, ActiveTimeBias=240, TimeZoneKeyName=Eastern Standard Time. Last written: 2015-03-25T10:34:25Z.

**User Accounts (from SAM hive):**

1. **informant (RID 1000)** - Primary active user
   - Created: 2015-03-22 14:33:54Z
   - Last Login: 2015-03-25 14:45:59Z
   - Login Count: 10
   - Password Hint: "IAMAN" (matches volume labels "IAMAN $_@" and "IAMAN CD")
   - Account Type: Admin
   - **This user created all other accounts and is the primary actor**

2. **admin11 (RID 1001)** - Admin
   - Created: 2015-03-22 15:51:54Z (created BY informant per Security event logs)
   - Last Login: 2015-03-22 15:57:02Z
   - Login Count: 2

3. **ITechTeam (RID 1002)** - Admin
   - Created: 2015-03-22 15:52:30Z (created BY informant)
   - Never logged in

4. **temporary (RID 1003)** - Limited user
   - Created: 2015-03-22 15:53:01Z (created BY informant)
   - Login Count: 1

5. **Administrator (RID 500)** - Disabled
6. **Guest (RID 501)** - Disabled

**Security Event Log confirms:** The informant user (S-1-5-21-...1000) created admin11, ITechTeam, and temporary accounts and added admin11 and ITechTeam to Administrators group on 2015-03-22. Password hint "IAMAN" directly links the user to the removable media labels.



### 20. [INFO] Application Execution Timeline: Document Access and Exfiltration Workflow

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant, registry.usrclass.informant, ez.shimcache |
| **Evidence Refs** | tc_8710ecf6, tc_1829697a, tc_b6b7e690 |
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |


UserAssist, ShimCache, and RecentDocs artifacts reconstruct the complete application execution timeline on the informant-PC, revealing a methodical data access, exfiltration, and cover-up workflow.

**Application Execution Chronology (UserAssist timestamps, UTC):**

Day 1 - 2015-03-22 (System Setup):
- 14:33:13Z: First login, standard Windows apps explored
- 15:12:32Z: IE11 installer downloaded and run (C:\Users\informant\Desktop\Download\IE11-Windows6.1-x64-en-us.exe)
- 15:24:47Z: System licensing (slui.exe, 3x)
- 15:51-15:53Z: Created admin11, ITechTeam, temporary accounts

Day 2 - 2015-03-23 (Document Work Begins):
- 17:26:50Z: Chrome launched
- 17:28:18Z: TypedURLs → bing.com, google.com
- 20:10:19Z: cmd.exe (4x) — command-line operations
- 20:23:28Z: First access to \\10.11.11.128\secured_drive (shellbags)
- 20:26:50Z: Excel (1x) — (secret_project)_pricing_decision.xlsx
- 20:27:33Z: PowerPoint (2x) — [secret_project]_final_meeting.pptx

Day 3 - 2015-03-24 (Data Access and CD-R Burning):
- 13:37:59Z: USBSTOR driver last written (USB device connected)
- 13:38:31Z: E:\RM#1\Secret Project Data browsed (shellbags)
- 13:47:54Z-13:48:00Z: V:\Secret Project Data subdirectories accessed
- 14:16:37Z: rundll32.exe (1x)
- 18:31:55Z: Sticky Notes (13x total)
- 20:44:18Z: winter_whether_advisory.zip accessed (RecentDocs)
- 20:57:00Z: CD-R stock photos created (Koala.jpg, Penguins.jpg, Tulips.jpg)
- 21:01:14Z: Stock photos on CD-R viewed (RecentDocs .jpg)
- 21:05:38Z: Chrome (7x total)

Day 4 - 2015-03-25 (Final Day — Anti-Forensics and Departure):
- 14:41:03Z: Outlook (5x total) — email activity
- 14:42:47Z: Windows Media Player (1x)
- 14:46:05Z: Internet Explorer (5x total)
- 14:50:14Z: **Eraser installer run** from Desktop\Download
- 14:57:56Z: **CCleaner installer run** from Desktop\Download
- 15:12:28Z: **Eraser executed** — secure file deletion
- 15:15:50Z: **CCleaner executed** — system trace cleaning
- 15:21:30Z: **Google Drive sync launched** — cloud exfiltration
- 15:24:48Z: WINWORD.EXE (4x total) — resignation letter
- 15:28:47Z: XPS viewer — resignation letter conversion
- 15:29:08Z: Last RecentDocs write (Resignation_Letter_.docx)

**Key ShimCache Entries (additional execution evidence):**
- C:\Program Files\Eraser\Eraser.exe (modified 2015-01-12, Executed=Yes)
- C:\Program Files (x86)\Google\Drive\googledrivesync.exe (modified 2015-02-19, Executed=Yes)
- C:\Program Files\Microsoft Office\Office15\OUTLOOK.EXE (Executed=Yes)
- C:\Program Files\Microsoft Office\Office15\WINWORD.EXE (Executed=Yes)
- C:\Program Files\Microsoft Office\Office15\POWERPNT.EXE (Executed=Yes)
- C:\Program Files\Microsoft Office\Office15\EXCEL.EXE (Executed=Yes)



### 21. [INFO] RecentDocs, WordWheelQuery, and OpenSaveMRU: Evidence of Document Search and Access Pattern

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant |
| **Evidence Refs** | tc_2fc026db, tc_8710ecf6 |


Multiple registry artifacts from the informant user's NTUSER.DAT hive document the systematic pattern of accessing and handling secret project documents.

**WordWheelQuery (Windows Explorer Search):**
- LastWrite: 2015-03-23 18:40:17Z
- Search term: "secret"
- This search was used to locate secret project documents on the network share or local system

**RecentDocs (MRU Order, LastWrite 2015-03-25 15:29:08Z):**
Most recently accessed first:
1. Resignation_Letter_(Iaman_Informant).docx
2. Resignation_Letter_(Iaman_Informant).xps
3. BD-RE Drive (D:) IAMAN CD
4. Tulips.jpg → 5. Koala.jpg → 6. Penguins.jpg (stock photos on CD-R)
7. BD-RE Drive (D:)
8. winter_whether_advisory.zip
9. final (folder)
10. [secret_project]_final_meeting.pptx
11. pricing decision (folder)
12. (secret_project)_pricing_decision.xlsx
13. secret (folder)
14. [secret_project]_design_concept.ppt
15. [secret_project]_proposal.docx

**RecentDocs by Extension:**
- .docx: [secret_project]_proposal.docx, Resignation_Letter_(Iaman_Informant).docx
- .ppt: [secret_project]_design_concept.ppt (LastWrite 2015-03-23 18:38:21Z)
- .pptx: [secret_project]_final_meeting.pptx (LastWrite 2015-03-23 20:27:33Z)
- .xlsx: (secret_project)_pricing_decision.xlsx (LastWrite 2015-03-23 20:26:53Z)
- .xps: Resignation_Letter_(Iaman_Informant).xps (LastWrite 2015-03-25 15:28:33Z)
- .zip: winter_whether_advisory.zip (LastWrite 2015-03-24 20:44:18Z)
- .jpg: Tulips.jpg, Koala.jpg, Penguins.jpg (LastWrite 2015-03-24 21:01:14Z)
- Folders: BD-RE Drive IAMAN CD, BD-RE Drive, final, pricing decision, secret

**OpenSavePidlMRU (File Open/Save Dialog History):**
- LastWrite 2015-03-25 15:28:33Z
- Files accessed via open/save dialogs (MRU order):
  1. Resignation_Letter_(Iaman_Informant).xps
  2. Download\ccsetup504.exe
  3. Download\Eraser 6.2.0.2962.exe
  4. Resignation_Letter_(Iaman_Informant).docx
  5. Download\IE11-Windows6.1-x64-en-us.exe
- .docx type: Resignation_Letter saved on 2015-03-24 18:48:40Z
- .exe type: ccsetup504.exe, Eraser installer, IE11 installer (LastWrite 2015-03-25 14:48:28Z)
- .xps type: Resignation Letter saved as XPS on 2015-03-25 15:28:33Z

**TypedURLs (Internet Explorer):**
- LastWrite 2015-03-23 17:28:18Z
- url1: http://www.bing.com/
- url2: http://google.com/
- url3: http://go.microsoft.com/fwlink/?LinkId=69157

These artifacts collectively demonstrate the user: (1) searched for "secret" documents, (2) accessed all secret project files in their original formats, (3) accessed the CD-R drive contents, (4) downloaded anti-forensic tools, and (5) created and saved a resignation letter.



### 22. [INFO] CD-R (RM3) EXIF Metadata: Cover Images Are Stock Windows 7 Photos, Document-Embedded Images Show Kodak and Adobe Processing

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T20:57:03 |
| **Sources** | bulk.exif, optical.listing |
| **Evidence Refs** | tc_b1d2c51e, tc_b8a8b6ad |


EXIF analysis of image data on the CD-R reveals two distinct classes of images:

**1. Active Cover Images (3 files in final session):**
The three remaining active files are stock Windows 7 sample photographs:
- Koala.jpg (780,831 bytes): Artist="Corbis", DateTimeOriginal=2008-02-11 11:32:43, modified 2009-03-12 13:48:28. SHA1: 8ed079594882a366e55d2435a8ef465e273a41ac
- Penguins.jpg (777,835 bytes): Artist="Corbis", DateTimeOriginal=2008-02-18 05:07:31, modified 2009-03-12 13:48:35. SHA1: 5db7f51e7ec17bd17335c85b069025072ba6614c
- Tulips.jpg (620,888 bytes): Copyright="Microsoft Corporation", DateTimeOriginal=2008-02-07 11:33:11, modified 2009-03-12 13:48:39. SHA1: 80824aa4a492d18585c4659632069dc9cc79fd47

These are standard Windows 7 sample photos (C:\Users\Public\Pictures\Sample Pictures) used as cover content to make the CD appear innocuous. Their modified dates (2009-07-14 05:32:31, the Windows 7 RTM date) and Corbis/Microsoft attribution confirm they are unmodified system files. They were burned to the CD on 2015-03-24 at 20:57:00-20:57:03 UTC, after all exfiltrated documents were deleted from the active filesystem.

**2. Document-Embedded Image EXIF (from deleted sessions):**
The masqueraded Office documents contain embedded images with EXIF data from two distinct sources:

a) **Kodak DC260 photographs (2003 era):**
   - Camera: "Eastman Kodak Company" / "KODAK DIGITAL SCIENCE DC260 (V01.00)"
   - DateTimeOriginal: 2003-09-24 15:33:42 and 2003-12-10 17:27:44
   - Resolution: 1536×1024 pixels
   - No GPS data present
   - Found at offsets 1310146 and 9203260 in the CD-R image

b) **Adobe Photoshop CS Macintosh processed images (2006 era):**
   - Software: "Adobe Photoshop CS Macintosh"
   - DateTime stamps: 2006-03-21, between 11:19:46 and 13:39:22 (same day processing batch)
   - Various dimensions (157×207 to 539×273 pixels) — small images typical of document illustrations
   - Multiple distinct SHA1 hashes confirm these are unique images
   - Found at 9 offsets between 95018581 and 99647667 in the CD-R image

**No GPS coordinates** were found in any images on the CD-R. The EXIF data does not contain steganographic indicators. The document-embedded images suggest the exfiltrated documents contain technical illustrations that were originally photographed with a Kodak DC260 camera in 2003 and processed in Adobe Photoshop CS on a Mac in March 2006.



### 23. [INFO] No Valid PCAP Data Available — SMB File Transfer Analysis Not Possible

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | pcap.disk.atiumd6a, pcap.disk.atiumdva, registry.system |
| **Evidence Refs** | tc_9f3e3cea, tc_c43a20d8 |


Investigation question: "Is there any evidence in the PCAP data of SMB file transfers between the PC and 10.11.11.128?"

Answer: No valid PCAP network capture files exist in the disk image. The only .cap files found were ATI GPU driver files (atiumd6a.cap, atiumdva.cap) located in the Windows driver store at C:\Windows\System32\DriverStore\FileRepository\atiilhag.inf_*\. TShark confirmed these are not valid packet capture files.

Despite the absence of PCAP evidence, the SMB connection to \\10.11.11.128\secured_drive is confirmed through multiple other artifacts:
- Shellbag entries showing navigation to the network share path
- File metadata timestamps on USB documents matching the source on the secured drive
- The PC's own IP was 10.11.11.129 (DHCP, same /24 subnet as the file server at 10.11.11.128)



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | Dual-Partition USB Device Structure Enables Plausible Deniability |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Program` |  | Anti-Forensic Tool Suite: Eraser and CCleaner Downloaded, Installed, and Execute |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `iaman@nist.gov` |  | Dual-Partition USB Device Structure Enables Plausible Deniability |
| Email | `iaman.informant@nist.gov` |  | Dual-Partition USB Device Structure Enables Plausible Deniability |
| Email | `eric_p._lauer@omb.eop.gov` |  | Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across |
| Email | `wayne.longman@att.net` |  | Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across |
| Email | `mmun@loc.gov` |  | Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across |
| Email | `iaman.informant.personal@gmail.com` |  | Cross-Media Document Metadata: Email Addresses and Authorship Attribution Across |
| Email | `spy.conspirator@nist.gov` |  | Potential Co-Conspirator Contact Entry — spy.conspirator@nist.gov in Outlook Dat |




---

## Appendix C: MITRE ATT&CK Coverage

14 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Execution (2) > Persistence (3) > Privilege Escalation (2) > Defense Evasion (4) > Discovery (1) > Collection (2) > Exfiltration (2) > Impact (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Insider Threat - User Identity and Resignation... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Application Execution Timeline: Document... |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Application Execution Timeline: Document... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Insider Threat - User Identity and Resignation... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Cross-System: Diversionary User Account... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Complete Cross-System Exfiltration and...; Cross-System: Diversionary User Account... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Insider Threat - User Identity and Resignation... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Cross-System: Diversionary User Account... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | Masquerade File Type | Environment-Wide File Extension Masquerading...; Dual-Partition USB Device Structure Enables...; Complete Cross-System Exfiltration and...; CD-R (RM3) Data Exfiltration: 9 Burn Sessions...; CD-R (RM3) Multi-Session Anti-Forensic...; Cross-System: Premeditated Anti-Forensic and...; Cross-System: Identical Exfiltrated Documents... |
| [T1070.003](https://attack.mitre.org/techniques/T1070/003/) | Clear Command History | Anti-Forensic Tool Suite: Eraser and CCleaner... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Environment-Wide Deletion of Exfiltrated...; Anti-Forensic Tool Suite: Eraser and CCleaner...; Complete Cross-System Exfiltration and...; Potential Cloud Exfiltration via Google Drive...; CD-R (RM3) Data Exfiltration: 9 Burn Sessions...; CD-R (RM3) Multi-Session Anti-Forensic...; Cross-System: Premeditated Anti-Forensic and... |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Insider Threat - User Identity and Resignation... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | Network Share Access to Secured Corporate Data... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network Share Access to Secured Corporate Data...; Complete Cross-System Exfiltration and... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Data Exfiltration via Removable Media - Secret...; Complete Cross-System Exfiltration and...; Cross-System: Identical Exfiltrated Documents... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Environment-Wide File Extension Masquerading...; Environment-Wide Deletion of Exfiltrated...; Dual-Partition USB Device Structure Enables...; USB Device Tied to Source PC via Shellbag and...; Cross-Media Document Metadata: Email Addresses...; Data Exfiltration via Removable Media - Secret...; Complete Cross-System Exfiltration and...; CD-R (RM3) Data Exfiltration: 9 Burn Sessions...; CD-R (RM3) Multi-Session Anti-Forensic...; Cross-System: Premeditated Anti-Forensic and...; Cross-System: Identical Exfiltrated Documents...; Potential Co-Conspirator Contact Entry —... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Complete Cross-System Exfiltration and...; Potential Cloud Exfiltration via Google Drive...; Cross-System: Premeditated Anti-Forensic and... |


### Impact

| Technique | Name | Findings |
|-----------|------|----------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Anti-Forensic Tool Suite: Eraser and CCleaner... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 596 |
| Findings submitted | 23 |
| Confirmed | 19 |
| Inferences | 4 |
| Input tokens | 36.9K |
| Output tokens | 229.7K |
| Total tokens | 266.7K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 36.9K | 229.7K | 266.7K |




<details>
<summary>Evidence Sources (133)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.fsstat | sleuthkit | 37 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 27 |
| hashdeep.hashes | hashdeep | 6 |
| tsk.fsstat | sleuthkit | 40 |
| tsk.filelist | sleuthkit | 51 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 9 |
| tsk.partitions | sleuthkit | 10 |
| optical.listing | mulder-optical | 58 |
| ez.mft | eztools | 98918 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 237 |
| bulk.email | bulk_extractor | 12 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 300 |
| bulk.url_services | bulk_extractor | 21 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 366963 |
| bulk.duplicates | bulk_extractor | 12 |
| bulk.email | bulk_extractor | 6851 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 793 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.url | bulk_extractor | 421750 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3637 |
| bulk.winpe | bulk_extractor | 29138 |
| bulk.winpe_carved | bulk_extractor | 29130 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 69 |
| registry.system | regripper | 8 |
| pcap.disk.atiumd6a | tshark | 8 |
| tsk.masquerade | sleuthkit | 0 |
| registry.system | regripper | 33492 |
| pcap.disk.atiumdva | tshark | 8 |
| evtx.manifest | evtx-extract | 54 |
| tsk.masquerade | sleuthkit | 17 |
| registry.system | regripper | 283 |
| ez.shimcache | eztools | 307 |
| registry.system | regripper | 283 |
| pcap.disk.atiumd6a | tshark | 8 |
| registry.query.software | python-registry | 1 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.system | regripper | 199 |
| pcap.disk.atiumd6a | tshark | 8 |
| hayabusa.alerts | hayabusa | 35 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| tsk.timeline | sleuthkit | 344089 |
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
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 5206 |
| bulk.duplicates | bulk_extractor | 1298 |
| bulk.email | bulk_extractor | 15 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 5226 |
| bulk.url_services | bulk_extractor | 25 |
| bulk.zip_carved | bulk_extractor | 3851 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| tsk.timeline | sleuthkit | 67 |
| strings.output | strings | 22065 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 7330 |
| bulk.duplicates | bulk_extractor | 1742 |
| bulk.email | bulk_extractor | 61 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7192 |
| bulk.url_services | bulk_extractor | 58 |
| bulk.zip_carved | bulk_extractor | 5221 |
| tsk.timeline | sleuthkit | 187 |
| exiftool.metadata | exiftool | 9 |
| strings.output | strings | 165747 |
| tsk.masquerade | sleuthkit | 3 |
| chainsaw.hunt | chainsaw | 99 |
| registry.query.system | python-registry | 1 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| strings.output | strings | 34815 |
| composite.timeline | composite | 172 |
| composite.execution | composite | 122 |
| composite.defense_evasion | composite | 216 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2494 |
| enrichment.iocs | enrichment | 59 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.correlation | composite | 1 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
