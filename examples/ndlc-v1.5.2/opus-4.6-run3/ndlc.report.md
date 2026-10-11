# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T16:08:05.031504+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 123 evidence sources (55 disk, 68 other) | 630 tool calls | 1.3 hours
**Results:** 24 findings (3 critical, 11 high) | 21 confirmed, 3 inference | 2 hypotheses ruled out
**Timeline:** 2014-12-01 to 2015-03-25

**Key Threats:**
- Cross-System Exfiltration Chain: Secret Project Documents Traced PC → RM1 → RM2 → RM3 Across 4 Evidence Sources
- Complete Anti-Forensic Countermeasure Sequence: Research → File Masquerading → Deletion → Tool Execution → Resignation
- Network Share \\10.11.11.128\secured_drive Identified as Original Source of Secret Project Documents — Shellbags Prove Network-to-USB-to-CD Chain

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-03-22 to 2015-03-24): Application Execution Summary: Office Suite, Email, Browser, and Data Transfer Tools Used for Exfiltration (+7 related)
- **Persistence** (2015-02-15 to 2015-03-25): Cross-System Exfiltration Chain: Secret Project Documents Traced PC → RM1 → RM2 → RM3 Across 4 Evidence Sources (+5 related)
- **Command and Control** (2014-12-04 to 2015-03-24): Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Removable Media (RM1, RM2, RM3) (+2 related)
- **Credential Access** (2014-12-01 to 2015-03-22): Massive File Extension Masquerading on RM2 - 17 Office Documents Disguised with False Extensions (+2 related)
- **Defense Evasion / Anti-Forensics** (2015-03-24): Deleted Cover Images on RM2 Suggest Anti-Forensic Concealment Strategy (+1 related)

**Tools:** search (175), get_raw_output (78), submit_finding (53), get_findings (26), delete_finding (23). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Cross-System Exfiltration Chain: Secret Project Documents Traced PC → RM1 → RM2 → RM3 Across 4 Evidence Sources** (2015-02-15T16:51:38 to 2015-03-24T20:57:03)


- **Complete Anti-Forensic Countermeasure Sequence: Research → File Masquerading → Deletion → Tool Execution → Resignation** (2015-03-23T14:59:57 to 2015-03-25T15:29:08)


- **Network Share \\10.11.11.128\secured_drive Identified as Original Source of Secret Project Documents — Shellbags Prove Network-to-USB-to-CD Chain** (2015-03-22T14:52:22 to 2015-03-24T20:57:03)




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

630 tool calls were executed across 24
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Insider Data Leakage Investigation — CFREDS 2015 Data Leakage Scenario

## Background

This investigation was initiated to examine suspected insider data theft involving the unauthorized exfiltration of sensitive government project documents from a National Institute of Standards and Technology (NIST) network environment. The case encompasses four forensic evidence images acquired from the suspect's workstation and three removable media devices, totaling 24 indexed evidence sources analyzed across 630 tool invocations. The investigation produced 24 formal findings, of which 21 were confirmed through corroborating evidence, 3 were assessed as analytical inferences, and 2 were ruled out as negative findings. A total of 15 distinct MITRE ATT&CK techniques were identified across the confirmed activity chain.

The evidence inventory consisted of the following four forensic images. First, the suspect's workstation PC (cfreds_2015_data_leakage_pc.E01), a Windows 7 system running as a VMware virtual machine with hostname "informant-PC," network address 10.11.11.129 on a local subnet alongside a file server at 10.11.11.128. The PC contained user profiles, registry hives, browser artifacts, MFT records, ShimCache, and event logs. Second, Removable Media 1 (cfreds_2015_data_leakage_rm1.E01), a USB flash drive formatted with exFAT, volume label "Authorized USB," serial number 5c75-4d3e, approximately 3.7 GB in capacity, containing active copies of secret project documents under their original filenames. Third, Removable Media 2 (cfreds_2015_data_leakage_rm2.E01), a USB flash drive formatted with FAT, volume label "IAMAN $_@," containing 17 deleted Office documents disguised with false file extensions alongside 22 deleted cover images. Fourth, Removable Media 3 (cfreds_2015_data_leakage_rm3_type3.E01), an optical disc (UDF write-once with VAT) labeled "IAMAN CD," containing the same 17 masqueraded documents burned across 9 UDF sessions, with three Windows sample photographs placed as cover content in the final session.

The suspect user account, "informant" (SID S-1-5-21-2425377081-3129163575-2985601102-1000, password hint "IAMAN"), was associated with the organizational email address iaman.informant@nist.gov. The PC's network configuration placed it on the same /24 subnet as the file server hosting the network share \\\\10.11.11.128\\secured_drive, which contained the original source documents. The V: drive on the PC was mapped to this network share, providing direct file-level access to the Secret Project Data repository.

## Incident Timeline

The incident unfolded across five distinct operational phases spanning approximately five weeks, from mid-February through late March 2015.

**Phase 1 — Initial Document Acquisition via RM1 (February 15, 2015).** The earliest exfiltration activity predates the suspect's PC by over a month. On February 15, 2015 at approximately 16:51–16:52 UTC, five secret project documents were copied to RM1 (the "Authorized USB" drive) in a directory structure "Secret Project Data/Secret Project Data/" with subdirectories for design and proposal files. These documents included [secret_project]_design_concept.ppt (1,810,432 bytes), [secret_project]_detailed_design.pptx (16,381,123 bytes), [secret_project]_revised_points.ppt (14,547,968 bytes), [secret_project]_detailed_proposal.docx (35,226,880 bytes), and [secret_project]_proposal.docx (6,484,502 bytes). A duplicate directory structure under "RM#1/Secret Project Data/" pointed to the same inode entries. The total data volume was approximately 74.4 MB. Since the suspect's PC was not created until March 22, 2015, this initial copy was performed from a different workstation. The original "Secret Project Data" root directory on RM1 was subsequently deleted on February 27, 2015 at 17:20:18 UTC, though the duplicate directory structure preserved access to the files.

**Phase 2 — PC Setup and Reconnaissance (March 22–23, 2015).** On March 22, 2015 beginning at 14:33:54 UTC, the suspect's workstation was provisioned with four user accounts created within approximately 90 seconds of each other: "informant" (RID 1000, the primary actor), "admin11" (RID 1001, IT administrator), "ITechTeam" (RID 1002, never logged in), and "temporary" (RID 1003, single login for testing). The "informant" account was the first created and subsequently logged in 10 times across four days (March 22–25). The suspect's first documented action was browsing the network share at \\\\10.11.11.128\\secured_drive beginning at 14:52:22, navigating through the Secret Project Data directory tree including Common Data, Past Projects, design, pricing decision, final, technical review, proposal, and progress subdirectories. The V: mapped drive was used to access the same content at 20:27:24 on March 23.

During March 23, the suspect conducted extensive web research demonstrating systematic preparation for the data theft operation. Search queries included "information leakage cases," "how to leak a secret," "leaking confidential information," "intellectual property theft," "anti-forensic tools" (85 URL hits carved from disk), "ccleaner" (65 hits), "eraser" (51 hits), "DLP DRM" (90 hits), "cd burning method," "external device and forensics," "cloud storage," "google drive," "security checkpoint cd-r," and multiple forensic awareness queries such as "digital forensics," "e-mail investigation," "windows event logs," and "what is windows system artifacts." The suspect downloaded the DEFCON 20 Anti-Forensics PDF by Perklin and visited the FBI's Intellectual Property Rights investigation page. Google Drive (googledrivesync.exe) was downloaded at 19:56:33 and iCloud (icloudsetup.exe) at 19:56:53, both from the NIST network (IP 129.6.58.42). Office applications were used to open secret project documents: Word accessed [secret_project]_proposal.docx at 18:38:21, PowerPoint opened [secret_project]_final_meeting.pptx at 20:27:33, and Excel opened pricing decision documents at 20:26:50. The suspect also searched for "secret" in Windows Explorer at 18:40:17.

**Phase 3 — Local Staging and RM2 USB Exfiltration (March 24, 2015 morning/afternoon).** On March 24, the suspect created a staging directory named "S data" on the Desktop to organize documents prior to transfer. Shellbag analysis revealed navigation of this directory between 13:38 and 13:52 UTC, with access to subdirectories mirroring the network share structure: Secret Project Data/final, pricing decision, progress, technical review, design, and proposal. The USB drive RM1 was mounted as E: at 13:21:10, and the suspect browsed E:\\RM#1\\Secret Project Data\\design at 13:38:31, verifying the existing USB contents.

Seventeen Office documents were then copied to RM2 with deliberate file extension masquerading. Each document was renamed with an innocuous extension to disguise its true content type: PowerPoint files became .amr and .zip, Word documents became .gif, .png, .svg, .one, and .txt, Excel files became .7z, .jpg, and .db, and OLE compound documents became .avi. The batch copy operation produced creation timestamps clustered between 09:59:27 and 10:00:18 UTC. The disguised files were organized into five subdirectories corresponding to project work streams (design, pricing, progress, proposal, technical review). Four of the 17 files matched RM1 documents exactly by byte size, and the remaining 13 represented additional project deliverables covering pricing analysis, progress reports, and technical reviews not present on RM1. Twenty-two personal photographs were also placed on RM2 as visual cover content. All files on RM2 were subsequently deleted, leaving only filesystem metadata and carved data in unallocated space.

**Phase 4 — Optical Disc Burning and Cover Operation (March 24, 2015 evening).** Beginning at approximately 19:47 UTC, the suspect prepared to burn data to the RM3 optical disc. A Windows sample photograph was deleted from the Recycle Bin at 19:51:47, and the suspect accessed Sample Pictures, Sample Music, and Sample Videos libraries between 19:52:06 and 19:52:58. The actual disc burning commenced at 20:44:18, when the suspect accessed winter_whether_advisory.zip (the masqueraded PPTX file) and the CD/DVD drive. Between 20:54:16 and 20:56:46 UTC, all 17 masqueraded documents were burned to the "IAMAN CD" disc in abbreviated directories: de (design), pd (pricing decision), prog (progress), prop (proposal), and tr (technical review). At 20:57:00–20:57:03, three Windows 7 sample images — Koala.jpg, Penguins.jpg, and Tulips.jpg — were burned as the final active UDF session, effectively overwriting the directory listing to display only innocuous cover content. The disc contained 9 total VAT generations reflecting multiple burn and deletion cycles. The suspect's RecentDocs registry confirmed access to "BD-RE Drive (D:) IAMAN CD" with a last-write time of 21:01:14 UTC.

Also during the evening of March 24, the suspect created the first draft of a resignation letter ("Resignation_Letter_(Iaman_Informant).docx") at 18:48:40 UTC using Microsoft Word.

**Phase 5 — Anti-Forensic Cleanup and Departure (March 25, 2015).** On the final day of recorded activity, the suspect executed a systematic cleanup sequence. Outlook was used for the last time at 14:41:03. At 14:47:40, the Eraser 6.2.0.2962 installer was executed from the Desktop\\Download directory, followed by the CCleaner 5.04 installer (ccsetup504.exe) at 14:48:28. The .NET Framework bootstrapper for Eraser ran at 14:50:15. Eraser was launched via its desktop shortcut at 15:12:28, and CCleaner64.exe followed at 15:15:50. Following the anti-forensic tool execution, the suspect accessed the Google Drive folder at 15:20:59 and ran googledrivesync.exe at 15:21:30. A Google account sign-in page (AccountChooser) was cached at 15:22:08, and an email-related page (emailhrd) was cached at 15:24:51. Word was executed for the final time at 15:24:48. The resignation letter was exported to XPS format at 15:28:33 and viewed with xpsrchvw.exe at 15:28:47. The final documented activity was a RecentDocs registry entry at 15:29:08 UTC.

## Key Findings

**Exfiltrated Document Corpus.** The stolen documents relate to NASA/JPL Mars exploration research, as confirmed by embedded email addresses of NASA/JPL personnel (David.Beaty@jpl.nasa.gov, Karen.L.Buxbaum@jpl.nasa.gov, mmeyer@mail.hq.nasa.gov), URLs referencing the Mars Exploration Program Analysis Group (mepag.jpl.nasa.gov), and hyperlinks to multiple U.S. government domains including NASA Goddard (ltpwww.gsfc.nasa.gov), the White House (whitehouse.gov), the Department of Energy (sc.doe.gov), the Library of Congress (hdl.loc.gov), and USGS (infotrek.er.usgs.gov). Additional embedded contacts included Eric_P._Lauer@omb.eop.gov (Office of Management and Budget), mmun@loc.gov (Library of Congress), and th276a@nih.gov (National Institutes of Health). The documents contained academic DOI references and embedded images processed with Adobe Photoshop CS on Macintosh systems in 2006, with original photographs captured by a Kodak DC260 camera in 2003. The combined unique document volume across all media was approximately 131 MB, with 5 original-named documents on RM1 and 17 masqueraded documents (including 4 duplicates of RM1 content plus 13 additional files) on RM2 and RM3.

**Cross-Device Document Correlation.** The investigation established definitive links between all three removable media devices through multiple independent forensic artifacts. Four documents matched exactly by file size between RM1 and RM2: [secret_project]_detailed_design.pptx matched winter_whether_advisory.zip at 16,381,123 bytes, [secret_project]_revised_points.ppt matched winter_storm.amr at 14,547,968 bytes, [secret_project]_detailed_proposal.docx matched a_gift_from_you.gif at 35,226,880 bytes, and [secret_project]_proposal.docx matched landscape.png at 6,484,502 bytes. Eleven embedded image SHA1 hashes matched identically across all three devices, and EXIF metadata signatures (Kodak DC260, Adobe Photoshop CS Macintosh) were consistent across all media. The URL histogram counts from bulk extractor analysis matched nearly identically between RM2 and RM3, confirming byte-identical document content.

**Network Share Origin.** Shellbag analysis conclusively identified the network file share \\\\10.11.11.128\\secured_drive as the original source repository. The share contained directories for Common Data, Past Projects, and Secret Project Data with subdirectories for all project work streams. The V: mapped drive on the PC referenced the same MFT file entries as the network share shellbag records (e.g., MFT ref 43045/1 for Secret Project Data), establishing that V: was an alias for the secured_drive share. The complete data flow chain was: network share (10.11.11.128) to V: mapped drive to local staging directory ("S data" on Desktop) to USB RM1 (E:) to USB RM2 to optical disc RM3 (D:).

**File Extension Masquerading.** On RM2 and RM3, all 17 Office documents were renamed with false extensions in a deliberate anti-forensic concealment effort. The masquerading used varied and contextually plausible extensions: .amr (audio), .zip and .7z (archives), .jpg, .gif, .png, .svg, and .tif (images), .avi (video), .db (database), .one (OneNote), and .txt (text). The filenames were crafted to appear personally innocuous — "winter_storm," "my_favorite_cars," "super_bowl," "a_gift_from_you," "diary" series. The tsk.masquerade detection tool identified all 17 files by comparing the file extension against the actual content signature (OLE, DOCX, PPTX, or XLSX). The investigation confirmed that no genuine archive files were used for data bundling; the .zip and .7z files on RM2 were actually a PowerPoint presentation and an Excel spreadsheet, respectively.

**Multi-Session Optical Disc Overwriting.** The RM3 optical disc exhibited 9 UDF VAT generations, revealing an iterative concealment strategy. The masqueraded documents were first burned in directories with abbreviated names, then burned again with full directory names in subsequent sessions, and finally overwritten with three innocuous Windows sample photographs as the active session. The suspect likely believed that overwriting the disc with cover images would render the previously burned sensitive documents inaccessible, not realizing that UDF VAT session history is fully recoverable through forensic analysis. The presence of both abbreviated and full directory names across sessions suggests the suspect experimented with the disc structure before settling on the final layout.

**Anti-Forensic Tool Deployment.** The suspect researched, downloaded, installed, and executed two dedicated anti-forensic tools on the final day of activity. Eraser 6.2.0.2962 (a secure file deletion tool) was installed from the Desktop\\Download directory at 14:47:40 and launched at 15:12:28 UTC. CCleaner 5.04 (a system cleaning tool designed to remove browser history, temporary files, and registry traces) was installed at 14:48:28 and launched at 15:15:50 UTC. Both tools' execution was confirmed through convergence of four independent artifact types: ShimCache entries with "Executed" flags, UserAssist records with run counts and timestamps, MFT entries for the installer and application files, and bulk-extracted download URLs from piriform.com and sourceforge.net. The browser history databases were successfully destroyed by CCleaner — no recoverable browser history files were found by the parse_browser_history tool. However, bulk extractor recovered extensive URL and search history from unallocated disk space and cached IE Temporary Internet Files, demonstrating the limitations of CCleaner's cleaning scope. The "S data" staging directory was also successfully deleted, as no trace remained in the MFT, likely through Eraser's secure deletion capability.

**Cloud Service Installation.** Google Drive and Apple iCloud were both downloaded, installed, and executed on the suspect's PC. Google Drive was last run on March 25 at 15:21:30, after anti-forensic tools were executed but before the resignation letter was finalized. The Google Drive download URL contained NIST IP address 129.6.58.42, confirming the download occurred from the organizational network. While both cloud services were operational, no direct evidence of document upload through these channels was recovered, likely due to the CCleaner execution that destroyed browser history and potentially sync logs. The contextual timing — cloud service execution interleaved with anti-forensic cleanup and resignation letter preparation — is inconsistent with routine personal use, though the absence of confirmed transfer data prevents definitive classification as an exfiltration channel.

**Resignation Letter.** The suspect created "Resignation_Letter_(Iaman_Informant).docx" on March 24 at 18:48:40 and exported it to XPS format on March 25 at 15:28:33, making it the last documented activity on the workstation. The document was edited using Microsoft Word (4 total executions, last at 15:24:48) and viewed with the XPS Reader at 15:28:47. This behavioral artifact provides the strongest indication of a departing insider, with the resignation letter creation occurring between the data exfiltration operations (March 24) and the anti-forensic cleanup (March 25).

**Negative Findings.** The investigation ruled out two potential hypotheses. No steganographic content was detected in any image files across all three removable media devices, confirming that file extension masquerading — not steganographic embedding — was the chosen concealment method. Additionally, no malware signatures or YARA rule matches were detected on any evidence source, confirming this was a data theft operation rather than a malware distribution scenario.

## Threat Intelligence and Attribution

The evidence conclusively identifies the actor as an organizational insider operating under the user account "informant" with the email identity iaman.informant@nist.gov. Attribution to this specific user account is established through convergent evidence from multiple independent sources: the RecentDocs registry linking document access to the informant profile, shellbag entries tracing the complete network-to-USB-to-CD exfiltration chain under the informant's USRCLASS.DAT hive, UserAssist records documenting application execution under the informant's session, the "IAMAN" password hint matching the RM2 volume label "IAMAN $_@" and RM3 volume label "IAMAN CD," and the resignation letter filename explicitly identifying "Iaman Informant" as the author.

The Tactics, Techniques, and Procedures (TTPs) are consistent with a motivated insider threat actor conducting a planned data exfiltration operation over multiple weeks. The operational pattern includes: collection from internal file shares (T1005, T1039), local data staging (T1074.001), exfiltration via physical media across multiple device types (T1052.001), file extension masquerading for concealment (T1036.007, T1036.008), indicator removal through file deletion and anti-forensic tool execution (T1070, T1070.004), and potential cloud exfiltration channel preparation (T1567, T1567.002). The suspect demonstrated above-average awareness of digital forensic methodology, as evidenced by the DEFCON anti-forensics PDF download, targeted web searches about Windows system artifacts and email investigation techniques, and the multi-layered concealment approach combining file renaming, media wiping, disc session overwriting, and dedicated cleanup tools.

This case does not involve external threat actors, command-and-control infrastructure, or exploitation of technical vulnerabilities. The insider leveraged legitimate access to the \\\\10.11.11.128\\secured_drive network share and standard Office applications to collect and transfer documents. No privilege escalation was required; the informant account possessed direct access to the sensitive share as part of normal duties.

## Impact Assessment

The scope of the data breach encompasses approximately 131 MB of unique government project documentation spanning all work streams of the "Secret Project" — design concepts, detailed designs, revised points, proposals, pricing decisions, progress reports, and technical review materials. The document modification dates range from December 1, 2014 through January 23, 2015, representing approximately two months of project deliverables. The content relates to NASA/JPL Mars exploration research and references personnel and resources across multiple U.S. government agencies including NASA, the Office of Management and Budget, the Library of Congress, the National Institutes of Health, the Department of Energy, USGS, and the Defense Logistics Agency.

The data was exfiltrated to three separate physical media devices, creating at least three independent copies of the stolen material outside organizational control. One compromised system was involved — the workstation at 10.11.11.129 — along with the network file share at 10.11.11.128 that served as the document source. Credential exposure was limited to the informant's own account (iaman@NIST.GOV, password hint "IAMAN"), which was used exclusively for legitimate access; no credential theft or privilege escalation was observed. However, the potential installation and use of Google Drive and iCloud introduces uncertainty regarding whether additional copies were transmitted to cloud storage services, a question that cannot be fully resolved due to the anti-forensic tool execution that destroyed relevant browser and application logs.

The persistence depth of this insider threat is primarily organizational rather than technical. No backdoors, scheduled tasks, or persistent malware were installed. The threat persists through the physical possession of three removable media devices containing copies of the stolen data, and potentially through cloud storage accounts that may hold additional copies.

## Immediate Tactical Containment

1. Disable the user account "informant" (SID S-1-5-21-2425377081-3129163575-2985601102-1000, iaman.informant@nist.gov, iaman@NIST.GOV) across all organizational authentication systems including Active Directory, Exchange/Office 365, VPN, and badge access.
2. Revoke all access to the network file share \\\\10.11.11.128\\secured_drive and audit the share's access control list to identify any other accounts with access to the Secret Project Data directories.
3. Physically seize and forensically preserve all three removable media devices: RM1 ("Authorized USB," exFAT, serial 5c75-4d3e, MD5 7cd7bc148d3a1e5f329cb3580d4d4f8f), RM2 ("IAMAN $_@," FAT, MD5 6cfbfdb14e0a504684a338b87362d753), and RM3 ("IAMAN CD," UDF, volume label "IAMAN CD").
4. Isolate the suspect workstation at IP 10.11.11.129 (hostname informant-PC) from the network to prevent any residual cloud sync activity from Google Drive or iCloud services.
5. Block the Google account "informant" (identified from cookie "informant@accounts.google.com") and coordinate with Google to preserve any Google Drive data associated with this account.
6. Issue a password reset for the iaman.informant@nist.gov Exchange/Office 365 account and preserve the associated mailbox data, including the OST file referenced in the evidence.
7. Audit access logs on file server 10.11.11.128 for all access to the secured_drive share during the period February 1 through March 25, 2015, to determine whether additional users or systems accessed or copied the Secret Project Data.
8. Terminate any active Apple iCloud sessions associated with the suspect's account and preserve iCloud data if organizational management tools permit.

## Strategic Remediation

The network file share \\\\10.11.11.128\\secured_drive containing the Secret Project Data lacked adequate access controls and monitoring. The suspect accessed all project work streams (design, pricing, proposals, progress reports, technical reviews) without triggering any alerts, indicating that no Data Loss Prevention (DLP) solution was monitoring file access patterns or bulk document copying from this share. Implementing DLP monitoring on sensitive network shares with alerting on anomalous access volume — specifically, bulk access to multiple project directories within a short timeframe, as occurred between March 22 and March 24 — would have provided early detection of the collection phase documented in finding f_94708e2a.

The suspect was able to connect personal USB devices (RM1 with volume label "Authorized USB" and RM2 with label "IAMAN $_@") and burn data to optical media (RM3 via the BD-RE drive mapped as D:) without restriction. The USB device with the label "Authorized USB" specifically suggests an attempt to circumvent physical media policies. Enforcing USB device whitelisting through Group Policy and disabling CD/DVD write capabilities on workstations that do not require them would have directly prevented the physical media exfiltration channels identified in findings f_315b96a8, f_9acf5bae, and f_19f6d9a7 (MITRE T1052.001).

The suspect researched and installed both Google Drive and Apple iCloud on the NIST workstation, establishing cloud exfiltration channels without organizational detection. The downloads originated from IP 129.6.58.42 on the NIST network, as documented in finding f_6ff0c8e4. Application whitelisting or Software Restriction Policies that prevent installation of unapproved cloud storage synchronization clients (googledrivesync.exe, iCloud.exe) would have blocked this potential exfiltration vector, which represents MITRE techniques T1567 and T1567.002.

The suspect downloaded and executed Eraser 6.2.0.2962 and CCleaner 5.04 from the internet on the final day of activity, successfully destroying browser history databases and the local staging directory, as documented in finding f_c55df8cd. The ability to install these tools without administrative approval or endpoint detection alerts indicates the absence of application control and endpoint monitoring. Deploying endpoint detection and response (EDR) capable of alerting on known anti-forensic tool execution — particularly Eraser and CCleaner being installed and run in rapid succession — would have provided real-time notification of evidence destruction activity.

The suspect exhibited clear behavioral indicators of an imminent insider threat over a compressed timeframe: the creation of a new user account, immediate access to sensitive file shares, extensive web searches about data leakage methods and anti-forensics, installation of cloud storage and cleanup tools, and creation of a resignation letter, all within four days (March 22–25). As documented across findings f_a5ac2a84 and f_dc318c38, these behavioral signals occurred in plain view but were not detected. Establishing a User Activity Monitoring (UAM) program for users with access to sensitive compartmented projects — particularly triggered by HR events such as resignation notices — would have flagged the correlated access-to-sensitive-data and search-for-anti-forensics pattern before the exfiltration was complete.

## Conclusion

**Q1. What systems were compromised?** One workstation was directly involved: the PC at IP 10.11.11.129 (hostname informant-PC), running Windows 7 as a VMware virtual machine. The network file share at \\\\10.11.11.128\\secured_drive was the source of the stolen documents. Three removable media devices received exfiltrated data: RM1 (USB, "Authorized USB"), RM2 (USB, "IAMAN $_@"), and RM3 (optical disc, "IAMAN CD"). Cloud storage accounts (Google Drive and potentially iCloud) may hold additional copies but could not be confirmed due to anti-forensic cleanup.

**Q2. How did the attacker gain initial access?** This was an insider threat scenario. The user "informant" (iaman.informant@nist.gov) possessed legitimate access to the workstation and the network file share as part of their organizational role at NIST. No unauthorized access, credential theft, or exploitation of vulnerabilities occurred. The informant account was created by IT administrators on March 22, 2015 as part of standard workstation provisioning.

**Q3. What lateral movement occurred?** No lateral movement in the traditional sense was observed. The suspect operated entirely within their authorized access scope, accessing the \\\\10.11.11.128\\secured_drive share via a mapped V: drive and copying data to local staging and removable media. The investigation found no evidence of access to systems beyond the assigned workstation and file server.

**Q4. What persistence mechanisms were installed?** N/A. No technical persistence mechanisms (backdoors, scheduled tasks, registry run keys, or implants) were installed. This was a data theft and departure operation, not a persistent access campaign. The "persistence" of the threat exists in the form of stolen data copies on physical media and potentially in cloud storage.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes. Approximately 131 MB of unique government project documentation was confirmed exfiltrated across three physical media devices. The documents relate to NASA/JPL Mars exploration research and span five project work streams: design, pricing, proposals, progress tracking, and technical reviews. Five documents with original filenames were placed on RM1 (74.4 MB), and 17 documents (including 4 duplicates of RM1 content plus 13 additional files totaling 87.3 MB) were placed on RM2 and RM3 with disguised file extensions. Additional cloud exfiltration via Google Drive or iCloud is suspected but unconfirmed.

**Q6. What is the full timeline of the incident?** The incident spanned from February 15, 2015 (first confirmed document copy to RM1) through March 25, 2015 (final anti-forensic cleanup and resignation letter creation). The primary operational period was March 22–25, 2015: PC setup and network share reconnaissance on March 22, document access and anti-forensic research on March 23, local staging, USB copy, and CD burning on March 24, and tool-assisted cleanup with resignation letter finalization on March 25.

**Q7. What is the total scope and business impact?** The breach exposed sensitive government project documentation related to NASA/JPL Mars exploration research, with embedded references to personnel and resources across NASA, JPL, OMB, the Library of Congress, NIH, DOE, USGS, and the Defense Logistics Agency. Three physical copies of the stolen data exist outside organizational control, and cloud copies may exist as well. The suspect's demonstrated awareness of forensic techniques (evidenced by the DEFCON anti-forensics PDF download, FBI IPR page visit, and systematic cleanup) indicates this was a deliberate, premeditated operation rather than an impulsive act, which elevates the risk of the data being shared or used for unauthorized purposes.

**Q8. What are the recommended remediation actions?** The five strategic remediation actions detailed above directly address the root causes identified in this investigation: implement DLP monitoring on sensitive file shares, enforce USB device whitelisting and optical media write restrictions, deploy application control to prevent unauthorized cloud storage and anti-forensic tool installation, implement endpoint detection for known evidence destruction tools, and establish User Activity Monitoring for personnel with access to sensitive projects, with heightened scrutiny during employee departure windows.


---

## Overview

| | |
|---|---|
| Findings | **24** (21 confirmed, 3 inference) |
| Severity | 3 critical, 11 high, 4 medium, 0 low, 6 info |
| Sources | 24 evidence sources across 630 tool calls |
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
| 2014-12-01T14:50:26 | Massive File Extension Masquerading on RM2 - 17 Office Documents Disguised with False Extensions | HIGH | tsk.filelist, tsk.masquerade, tsk.timeline |
| 2014-12-04T11:24:50 | Sensitive "Secret Project" Documents Found on USB Device RM1 | HIGH | tsk.fsstat, tsk.filelist, tsk.timeline, bulk.email |
| 2014-12-04T11:24:50 | Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Removable Media (RM1, RM2, RM3) | HIGH | bulk.email, bulk.url_services, bulk.exif, bulk.rfc822 |
| 2015-02-15T16:51:38 | Cross-System Exfiltration Chain: Secret Project Documents Traced PC → RM1 → RM2 → RM3 Across 4 Evidence Sources | CRITICAL | bulk.exif, ez.shimcache, optical.listing, registry.ntuser.informant, registry.sam, tsk.filelist, tsk.masquerade, tsk.timeline |
| 2015-03-22T14:33:13 | Application Execution Summary: Office Suite, Email, Browser, and Data Transfer Tools Used for Exfiltration | INFO | registry.ntuser.informant, registry.system |
| 2015-03-22T14:33:54 | Network Configuration: PC at 10.11.11.129 on Same Subnet as File Server 10.11.11.128 | INFO | registry.system |
| 2015-03-22T14:33:54 | PC User Accounts Analysis: informant (Primary Actor), admin11/ITechTeam/temporary (Administrative Setup Accounts) | INFO | registry.sam, ez.mft, tsk.timeline |
| 2015-03-22T14:34:41 | PC User "informant" Accessed Secret Project Documents Prior to USB Copy | HIGH | ez.mft, tsk.filelist |
| 2015-03-22T14:52:22 | Network Share \\10.11.11.128\secured_drive Identified as Original Source of Secret Project Documents — Shellbags Prove Network-to-USB-to-CD Chain | CRITICAL | registry.usrclass.informant, tsk.timeline, optical.listing |
| 2015-03-22T15:48:40 | Microsoft Outlook Email Client Used with iaman.informant@nist.gov Account | INFO | registry.ntuser.informant, bulk.domain, tsk.filelist |
| 2015-03-23T14:59:57 | Complete Anti-Forensic Countermeasure Sequence: Research → File Masquerading → Deletion → Tool Execution → Resignation | CRITICAL | bulk.url, bulk.url_searches, composite.recovery, ez.mft, ez.shimcache, optical.listing, registry.ntuser.informant, tsk.masquerade, tsk.timeline |
| 2015-03-23T14:59:57 | PC Search History Reveals Extensive Insider Threat Research - Data Leakage Methods, Anti-Forensics, and Evidence Destruction | HIGH | bulk.url_searches |
| 2015-03-23T19:56:33 | Google Drive and iCloud Installed and Executed — Cloud Exfiltration Channels Prepared But No Confirmed Data Transfer | MEDIUM | ez.shimcache, registry.ntuser.informant, bulk.url, bulk.url_searches |
| 2015-03-24T09:59:27 | Deleted Cover Images on RM2 Suggest Anti-Forensic Concealment Strategy | MEDIUM | tsk.filelist, bulk.rfc822 |
| 2015-03-24T13:47:58 | Local "S data" Staging Directory on Desktop Used for Data Collection Before USB/CD Transfer | HIGH | registry.usrclass.informant |
| 2015-03-24T15:51:47 | All Files on RM2 Are Deleted — Device Was Wiped After Use | HIGH | tsk.filelist, bulk.zip_carved |
| 2015-03-24T18:48:40 | Resignation Letter Created on Final Day Corroborates Insider Threat Departing Organization | HIGH | registry.ntuser.informant, tsk.timeline, ez.mft |
| 2015-03-24T19:51:47 | PC Recycle Bin Contains Deleted Windows Sample Photo — Preparation for Optical Disc Cover Content | MEDIUM | ez.mft, tsk.filelist |
| 2015-03-24T20:44:18 | PC Registry and Timeline Prove User "informant" Burned Data to CD on March 24, 2015 Evening | HIGH | registry.ntuser.informant, tsk.timeline, optical.listing |
| 2015-03-24T20:54:16 | Multi-Session Disc Burning Shows Concealment Strategy — Files Overwritten with Cover Images | HIGH | optical.listing |
| 2015-03-24T20:54:16 | EXIF Hash-Level Confirmation: Embedded Document Images Match Across RM1, RM2, and RM3 | HIGH | bulk.exif |
| 2015-03-25T15:22:08 | Google Account Authentication Confirms Webmail Access: "informant@accounts.google.com" Cookie Carved from PC | MEDIUM | bulk.email, ez.mft, bulk.url |




---

## Hypotheses Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No Steganography or Malware Signatures Detected on Any Removable Media (RM1, RM2, RM3)** : Steganography scanning and YARA signature scanning were executed against all removable media images and returned no detections:

- Steganography detection (steg.*): No hidden data detected in any...

- **No Genuine Archive Files Used for Data Bundling — .zip and .7z Files Are Masqueraded Office Documents** : Investigation question: Were archive files (ZIP, RAR, 7z) used to bundle data for exfiltration?

Finding: No genuine archive files were found on RM2. Two files with archive extensions exist but...



---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Cross-System Exfiltration Chain: Secret Project Documents Traced PC → RM1 → RM2 → RM3 Across 4 Evidence Sources

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-24T20:57:03 |
| **Sources** | bulk.exif, ez.shimcache, optical.listing, registry.ntuser.informant, registry.sam, tsk.filelist, tsk.masquerade, tsk.timeline |
| **Evidence Refs** | tc_6076ddf1, tc_7ed49de4, tc_8f67c2bd, tc_dc24ee7e |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


A complete chain of custody for secret project documents has been established across all four evidence sources (PC, RM1, RM2, RM3), proving a coordinated, multi-phase insider data exfiltration operation by user "informant" (iaman.informant@nist.gov).

**PHASE 1 — PC Document Access (Mar 22–23, 2015):**
User "informant" (created 2015-03-22T14:33:54, Password Hint: "IAMAN") accessed secret project documents from the PC. RecentDocs registry shows access to:
- [secret_project]_proposal.docx (2015-03-23T18:38:21)
- [secret_project]_design_concept.ppt (2015-03-23T18:38:21)
- [secret_project]_final_meeting.pptx (2015-03-23T20:27:33)
- (secret_project)_pricing_decision.xlsx (2015-03-23T20:26:53)
- Multiple project directories accessed: "secret", "pricing decision", "final"

**PHASE 2 — Copy to RM1 (Feb 15, 2015):**
5 documents copied to RM1 ("Authorized USB", exFAT, serial 5c75-4d3e) with original names in "Secret Project Data/" directory structure at 16:51–16:52 UTC. Total ~74.4 MB.

**PHASE 3 — Copy to RM2 with Masquerading (Mar 24, 2015 09:54–10:00 UTC):**
17 documents (including the same 4 files from RM1 matched by exact file size) copied to RM2 ("IAMAN $_@", FAT) with deliberate file extension masquerading — Office documents renamed with false extensions (.amr, .zip, .jpg, .avi, .gif, .png, .svg, .7z, .db, .one, .txt). All subsequently deleted.

**PHASE 4 — Burn to CD RM3 (Mar 24, 2015 20:54–20:56 UTC):**
Same 17 masqueraded documents burned to optical disc RM3 (volume label: "IAMAN CD", UDF with 9 VAT generations). Files placed in abbreviated directories (de=design, pd=pricing decision, prog=progress, prop=proposal, tr=technical review). All 17 files subsequently deleted through multi-session UDF overwriting. Three Windows sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) remain as cover content.

**CROSS-SYSTEM CONVERGENCE:**
- File sizes match exactly across RM1↔RM2 (4 files confirmed byte-identical)
- File sizes match exactly across RM2↔RM3 (all 17 files confirmed byte-identical)
- SHA1 hashes of 11 embedded images match between RM1 and RM2 (EXIF data)
- Same masqueraded filenames used on both RM2 and RM3
- Volume labels correlate: RM2="IAMAN $_@", RM3="IAMAN CD", PC user email=iaman@NIST.GOV
- RecentDocs on PC show "BD-RE Drive (D:) IAMAN CD" confirming PC-to-CD connection
- Timestamps form a coherent kill chain: PC access (Mar 23) → RM2 copy (Mar 24 AM) → CD burn (Mar 24 PM)

**Merged findings:**
- **RM3 Optical Disc Contains Identical Masqueraded Documents as RM2 — Third Exfiltration Medium Confirms Data Duplication** (f_1b2b7588, high, confirmed): The optical disc RM3 (cfreds_2015_data_leakage_rm3_type3.E01, volume label "IAMAN CD", UDF write-once with VAT, 9 sessions) contains the same 17 masqueraded documents found on RM2. This establishes RM3 as a third independent exfiltration medium, burned from the PC on March 24, 2015 approximately 11 hours after the RM2 USB copy.

**File Size Matches (RM2 ↔ RM3 — all 17 files identical):**
Design: winter_storm.amr (14,547,968), winter_whether_advisory.zip (16,381,123)
Pricing: my_favorite_cars.db (1,260,544), my_favorite_movies.7z (100,078), new_years_day.jpg (10,237,535), super_bowl.avi (10,289,152)
Progress: my_friends.svg (58,368), my_smartphone.png (4,440,235), new_year_calendar.one (27,414)
Proposal: a_gift_from_you.gif (35,226,880), landscape.png (6,484,502)
Technical: diary_#1d.txt (121,441), diary_#1p.txt (458,267), diary_#2d.txt (658,922), diary_#2p.txt (1,154,560), diary_#3d.txt (2,360,832), diary_#3p.txt (325,120)

**CD Burning Timeline (March 24, 2015):**
- 20:54:16 — /de (design) directory created, winter_storm.amr burned
- 20:54:42 — winter_whether_advisory.zip burned
- 20:55:00–20:55:07 — /pd (pricing) directory + 4 files
- 20:55:18–20:55:22 — /prog (progress) directory + 3 files
- 20:55:22–20:55:40 — /prop (proposal) directory + 2 files
- 20:55:43–20:55:46 — /tr (technical) directory + 6 files

**Multi-Session Deletion Pattern:**
Files were burned then systematically deleted across 7 UDF sessions (sessions -1 through -7), with the full directory names (design, pricing decision, progress, proposal, technical review) visible in earlier sessions. Three Windows sample images (Koala.jpg=780,831b, Penguins.jpg=777,835b, Tulips.jpg=620,888b) remain present as cover content, created at 2015-03-24T20:57:00.

**PC Connection Evidence:**
RecentDocs on PC show: "BD-RE Drive (D:) IAMAN CD" and "BD-RE Drive (D:)" — confirming the CD was burned from the informant's PC. The "IAMAN CD" volume label directly matches the user's email prefix (iaman@NIST.GOV).

**Affected Systems:** bulk.exif, ez.shimcache, optical.listing, registry.ntuser.informant, registry.sam, tsk.filelist, tsk.masquerade, tsk.timeline



### 2. [CRITICAL] Complete Anti-Forensic Countermeasure Sequence: Research → File Masquerading → Deletion → Tool Execution → Resignation

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T14:59:57 to 2015-03-25T15:29:08 |
| **Sources** | bulk.url, bulk.url_searches, composite.recovery, ez.mft, ez.shimcache, optical.listing, registry.ntuser.informant, tsk.masquerade, tsk.timeline |
| **Evidence Refs** | tc_1368c223, tc_1d7d5dec, tc_6076ddf1, tc_7ed49de4, tc_8f67c2bd |
| **ATT&CK** | [T1027](https://attack.mitre.org/techniques/T1027/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1070](https://attack.mitre.org/techniques/T1070/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Cross-system evidence reveals a systematic, multi-layered anti-forensic countermeasure sequence executed by user "informant" across all evidence sources:

**LAYER 1 — Research Phase (Mar 23, 2015):**
- Searched "anti-forensic tools" (85 URL hits), "anti-forensics", downloaded DEFCON-20 AntiForensics PDF
- Searched "ccleaner" (65 hits), "eraser" (51 hits), "system cleaner", "how to delete data"
- Searched "DLP DRM" (90 hits) to understand data loss prevention bypass
- Searched "digital forensics", "e-mail investigation", "windows system artifacts"
- Visited FBI Intellectual Property Rights investigation page
Source: bulk.url_searches (PC)

**LAYER 2 — File Extension Masquerading (Mar 24, 2015 09:59–10:00):**
- 17 Office documents renamed with false extensions on RM2 (.amr, .zip, .jpg, .avi, .gif, .png, .svg, .7z, .db, .one, .txt)
- Same masqueraded files burned to CD RM3 at 20:54–20:56
Sources: tsk.masquerade (RM2), optical.listing (RM3)

**LAYER 3 — File Deletion Across All Media:**
- RM1: Original "Secret Project Data" directory deleted 2015-02-27T17:20:18
- RM2: All 17 masqueraded files + 22 cover images deleted (device wiped)
- RM3: All 17 files deleted through multi-session UDF overwriting (7 deletion sessions)
- PC: Files in Recycle Bin ($RJEMT64.exe at inode 74398 from 2015-03-24T20:11:42)
Sources: tsk.timeline (RM1, RM2), optical.listing (RM3), tsk.timeline (PC)

**LAYER 4 — Anti-Forensic Tool Execution (Mar 25, 2015):**
- 14:47: Eraser 6.2.0.2962 installer executed from Desktop\Download
- 14:48: CCleaner 5.04 installer (ccsetup504.exe) executed from Desktop\Download
- 14:50: Eraser .NET Framework bootstrapper executes
- 15:12: Eraser.exe launched (1 run via UserAssist)
- 15:15: CCleaner64.exe launched (1 run via UserAssist)
Sources: ez.shimcache, registry.ntuser.informant (UserAssist), composite.recovery

**LAYER 5 — Cover Story Preparation (Mar 24–25, 2015):**
- Cover images placed on RM2 (22 personal photos) and RM3 (3 Windows sample images)
- Google Drive and iCloud installed (plausible deniability for cloud usage)
- Resignation letter created/exported to XPS (2015-03-25T15:24–15:28)

**Assessment:**
The anti-forensic sequence demonstrates sophisticated awareness of digital forensics methodology, consistent with the DEFCON presentation download and extensive web research. Despite these countermeasures, the user failed to:
1. Wipe the shimcache/UserAssist entries proving tool execution
2. Remove MFT entries for CCleaner/Eraser files
3. Sanitize RecentDocs registry showing document access
4. Account for bulk_extractor carving of deleted content
5. Remove the USBSTOR registry evidence
6. Destroy the UDF session history on the optical disc

**Merged findings:**
- **Confirmed Execution of Anti-Forensic Tools CCleaner and Eraser — Corroborated by Shimcache, UserAssist, MFT, and URL History** (f_3a121110, high, confirmed): Both CCleaner and Eraser were not merely researched but actually downloaded, installed, and executed on the PC by user "informant". This is confirmed by convergence of 4+ independent evidence sources:

**CCleaner (Evidence Destruction Tool):**
- Shimcache: C:\Program Files\CCleaner\CCleaner64.exe, Modified 2015-03-13T11:10:26, Executed=Yes (entry #61)
- Shimcache: C:\Program Files\CCleaner\CCleaner.exe, Modified 2015-03-13T11:10:26, Executed=Yes (entry #62)
- UserAssist: CCleaner64.exe run 1 time, last execution 2015-03-25T15:15:50
- UserAssist shortcut: C:\Users\Public\Desktop\CCleaner.lnk launched 2015-03-25T15:15:50
- Shimcache: Installer ccsetup504.exe from Desktop\Download executed (entry #83, modified 2015-03-25T14:48:28)
- Shimcache: uninst.exe from CCleaner directory executed (entry #51, modified 2015-03-13T13:55:38)
- MFT: CCleaner Lang directory files created 2015-03-13T13:54:30 (installation)
- MFT: CCleaner files accessed 2015-03-25T14:58:35 (execution day)
- bulk.url: Download URLs for piriform.com/ccleaner/download and download.piriform.com/ccsetup504.exe

**Eraser (Secure File Deletion Tool):**
- Shimcache: C:\Program Files\Eraser\Eraser.exe, Modified 2015-01-12T22:56:36, Executed=Yes (entry #19)
- UserAssist: Eraser.exe run 1 time, last execution 2015-03-25T15:12:28
- UserAssist shortcut: C:\Users\Public\Desktop\Eraser.lnk launched 2015-03-25T15:12:28
- Shimcache: Installer "Eraser 6.2.0.2962.exe" from Desktop\Download executed (entry #118, modified 2015-03-25T14:47:40)
- Shimcache: dotNetFx40_Full_setup.exe bootstrapper from eraserInstallBootstrapper executed (entry #117, modified 2015-03-25T14:50:15)
- bulk.url: Download URLs for sourceforge.net/project/eraser/Eraser%206/6.2/Eraser%206.2.0.2962.exe
- composite.recovery: Eraser detected as anti-forensic tool in secure_delete_tool category

**Execution Timeline (March 25, 2015):**
14:47:40 — Eraser installer downloaded/executed
14:48:28 — CCleaner installer downloaded/executed
14:50:15 — Eraser .NET bootstrapper runs
~14:58 — CCleaner installed (MFT access times)
15:12:28 — Eraser launched via desktop shortcut
15:15:50 — CCleaner launched via desktop shortcut

This confirms the user deliberately installed and ran both anti-forensic tools on the final day of activity (March 25), after all data exfiltration was complete. The tools were executed in sequence — Eraser first for secure file deletion, then CCleaner for trace cleanup.

**Affected Systems:** bulk.url, bulk.url_searches, composite.recovery, ez.mft, ez.shimcache, optical.listing, registry.ntuser.informant, tsk.masquerade, tsk.timeline



### 3. [CRITICAL] Network Share \\10.11.11.128\secured_drive Identified as Original Source of Secret Project Documents — Shellbags Prove Network-to-USB-to-CD Chain

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22 to 2015-03-24T20:57:03 |
| **Sources** | registry.usrclass.informant, tsk.timeline, optical.listing |
| **Evidence Refs** | tc_33cf3d3a, tc_235e73fc |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1039](https://attack.mitre.org/techniques/T1039/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Shellbag registry analysis of the informant's USRCLASS.DAT reveals the complete path from the original document source through all exfiltration media. The secret project documents were sourced from a network file share at \\\\10.11.11.128\\secured_drive.

**ORIGINAL SOURCE — Network Share (first accessed 2015-03-22T14:52:22):**
The user browsed a network share at \\\\10.11.11.128\\secured_drive containing:
- Common Data/
- Past Projects/
- Secret Project Data/
  - design/
  - pricing decision/
  - final/
  - technical review/
  - proposal/
  - progress/

This directory structure exactly matches the categories found on RM2 and RM3. The share was accessed first on 2015-03-22 (PC setup day) and again on 2015-03-23T20:23:28.

**MAPPED DRIVE V:\ — Same Network Share (accessed 2015-03-23T20:27:24):**
The network share was mapped as drive V:\ on the PC:
- V:\\Secret Project Data (MFT ref 43045/1, accessed 2015-03-23T20:27:24)
- V:\\Secret Project Data\\final (MFT ref 43048/1, accessed 2015-03-23T20:27:29)
The MFT file references match the network share shellbag entries, confirming V: is the same \\\\10.11.11.128\\secured_drive.

**LOCAL STAGING — "S data" Directory (accessed 2015-03-24T13:38-13:52):**
Documents were staged to a local directory containing the full project structure:
- S data\\Secret Project Data\\Common Data
- S data\\Secret Project Data\\design (MFT 46256/14)
- S data\\Secret Project Data\\proposal (MFT 62479/4)
- S data\\Secret Project Data\\pricing decision (MFT 71735/4)
- S data\\Secret Project Data\\progress (MFT 73368/7)
- S data\\Secret Project Data\\technical review (MFT 74299/9)
- S data\\Secret Project Data\\final (MFT 71686/14)
- S data\\Secret Project Data\\Past Projects (MFT 71165/4)
- S data\\Secret Project Data\\Secret Project Data\\design (MFT 71493/3)

**USB DRIVE E:\ — RM1 (accessed 2015-03-24T13:38:31):**
Shellbags show navigation of E:\\RM#1\\Secret Project Data\\design and E:\\Secret Project Data\\ with all subdirectories.

**OPTICAL DRIVE D:\ — RM3 CD Burning (accessed 2015-03-24T19:47-20:44):**
Shellbags show D: drive access with abbreviated directory names matching the CD:
- D:\\de (design), D:\\tr (technical), D:\\pd (pricing), D:\\prop (proposal), D:\\prog (progress)
- D:\\de\\winter_whether_advisory.zip was opened — file size [16,381,123] matches the masqueraded PPTX

**ADDITIONAL STAGING EVIDENCE:**
- Sample Pictures accessed 2015-03-24T14:44:23 (source of Koala.jpg, Penguins.jpg, Tulips.jpg cover images on RM3)
- Google Drive folder accessed 2015-03-25T15:20:59
- Programs and Features opened 2015-03-25T15:19:20 (reviewing installed software)

**COMPLETE CHAIN:** Network share (10.11.11.128) → V: mapped drive → Local staging (S data) → USB RM1 (E:) → USB RM2 → CD RM3 (D:)



### 4. [HIGH] Sensitive "Secret Project" Documents Found on USB Device RM1

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-04T11:24:50 to 2015-03-23T14:38:46 |
| **Sources** | tsk.fsstat, tsk.filelist, tsk.timeline, bulk.email |
| **Evidence Refs** | tc_844d930d, tc_2e261476, tc_bbeddb11, tc_b71bcf8a |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The removable media device RM1 (exFAT filesystem, Volume Label: "Authorized USB", Volume Serial: 5c75-4d3e, ~3.7 GB) contains 5 active corporate project documents in a directory structure "Secret Project Data/Secret Project Data/" with two subdirectories (design/ and proposal/):

**Design documents:**
- [secret_project]_design_concept.ppt (1,810,432 bytes, modified 2014-12-04T11:24:50)
- [secret_project]_detailed_design.pptx (16,381,123 bytes, modified 2014-12-16T11:10:26)
- [secret_project]_revised_points.ppt (14,547,968 bytes, modified 2015-01-23T15:47:10)

**Proposal documents:**
- [secret_project]_detailed_proposal.docx (35,226,880 bytes, modified 2014-12-18T16:50:58)
- [secret_project]_proposal.docx (6,484,502 bytes, modified 2014-12-19T14:53:46)

A duplicate directory structure exists under "RM#1/Secret Project Data/" with the same files (same inodes). The parent "Secret Project Data" directory at root is marked as deleted (d/d * 2054, deleted 2015-02-27T17:20:18). A deleted temporary Word file (~$ecret_project]_proposal.docx, 162 bytes) indicates one of the proposal documents was actively opened for editing. Total data volume of the 5 files: ~74.4 MB.

The documents contain references to NASA/JPL Mars exploration research with embedded hyperlinks to mepag.jpl.nasa.gov and academic DOI references. Bulk extractor carved email addresses from within the documents: David.Beaty@jpl.nasa.gov, Karen.L.Buxbaum@jpl.nasa.gov, and mmeyer@mail.hq.nasa.gov - all NASA/JPL personnel involved in Mars exploration programs.



### 5. [HIGH] Massive File Extension Masquerading on RM2 - 17 Office Documents Disguised with False Extensions

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-01T14:50:26 to 2015-03-24T10:00:18 |
| **Sources** | tsk.filelist, tsk.masquerade, tsk.timeline |
| **Evidence Refs** | tc_2e261476, tc_6cfb2fd3, tc_a8ebced2, tc_bbeddb11 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1036.007](https://attack.mitre.org/techniques/T1036/007/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The second removable media device (RM2, FAT filesystem, Volume Label: "IAMAN $_@") contains 17 deleted files in orphan directories where the file content signature contradicts the file extension. All files are actually Microsoft Office documents (OLE/docx/pptx/xlsx) renamed with innocuous extensions to disguise their true nature. This is a deliberate anti-forensic concealment technique.

**design/ directory (2 files):**
- winter_storm.amr → actually OLE (14,547,968 bytes, mtime 2015-01-23T16:47:10)
- winter_whether_advisory.zip → actually PPTX (16,381,123 bytes, mtime 2014-12-16T12:10:26)

**PRICIN~1/ directory (4 files):**
- my_favorite_cars.db → actually OLE (1,260,544 bytes, mtime 2015-01-16T15:10:24)
- my_favorite_movies.7z → actually XLSX (100,078 bytes, mtime 2015-01-08T17:08:24)
- new_years_day.jpg → actually XLSX (10,237,535 bytes, mtime 2014-12-01T14:50:26)
- super_bowl.avi → actually OLE (10,289,152 bytes, mtime 2014-12-02T13:28:58)

**progress/ directory (3 files):**
- my_friends.svg → actually OLE (58,368 bytes, mtime 2015-01-20T11:13:44)
- my_smartphone.png → actually DOCX (4,440,235 bytes, mtime 2015-01-05T11:57:22)
- new_year_calendar.one → actually DOCX (27,414 bytes, mtime 2015-01-12T14:23:42)

**proposal/ directory (2 files):**
- a_gift_from_you.gif → actually DOCX (35,226,880 bytes, mtime 2014-12-18T17:50:58)
- landscape.png → actually DOCX (6,484,502 bytes, mtime 2014-12-19T15:53:46)

**TECHNI~1/ directory (6 files):**
- diary_#1d.txt → actually DOCX (121,441 bytes, mtime 2015-01-05T17:01:08)
- diary_#1p.txt → actually PPTX (458,267 bytes, mtime 2015-01-05T15:15:08)
- diary_#2d.txt → actually DOCX (658,922 bytes, mtime 2015-01-12T17:25:40)
- diary_#2p.txt → actually OLE (1,154,560 bytes, mtime 2015-01-12T15:20:26)
- diary_#3d.txt → actually OLE (2,360,832 bytes, mtime 2015-01-20T16:05:00)
- diary_#3p.txt → actually OLE (325,120 bytes, mtime 2015-01-20T14:18:06)

All 17 files were deleted and recovered from orphan directories. All have creation times (crtime) around 2015-03-24T09:59-10:00, indicating a batch copy operation. The directory structure (design, pricing, progress, proposal, technical) suggests these are complete project deliverables organized by work stream.

**Merged findings:**
- **File Size Correlation Confirms RM1 and RM2 Contain Identical Secret Project Documents** (f_56f369a2, high, confirmed): Critical file size matching between RM1's openly-named "Secret Project" documents and RM2's disguised files confirms they contain the same documents. Four out of five RM1 files have exact byte-for-byte size matches on RM2:

**Exact matches:**
1. RM1: [secret_project]_detailed_design.pptx (16,381,123 bytes) = RM2: winter_whether_advisory.zip (16,381,123 bytes, detected as PPTX)
2. RM1: [secret_project]_revised_points.ppt (14,547,968 bytes) = RM2: winter_storm.amr (14,547,968 bytes, detected as OLE)
3. RM1: [secret_project]_detailed_proposal.docx (35,226,880 bytes) = RM2: a_gift_from_you.gif (35,226,880 bytes, detected as DOCX)
4. RM1: [secret_project]_proposal.docx (6,484,502 bytes) = RM2: landscape.png (6,484,502 bytes, detected as DOCX)

**Modification time correlation:**
The modification timestamps also closely match between devices (e.g., detailed_design.pptx mtime 2014-12-16T11:10:26 vs winter_whether_advisory.zip mtime 2014-12-16T12:10:26 - same day, 1 hour apart suggesting timezone or minor edit difference).

RM2 also contains 13 additional disguised files in pricing, progress, and technical directories not found on RM1, indicating RM2 carried an even larger set of exfiltrated project data covering all work streams. Total disguised data on RM2: ~87.3 MB across 17 files.

This proves the exfiltrator maintained copies of the same secret project documents across two separate USB devices, with RM2 using deliberate extension masquerading as an anti-forensic concealment technique.
- **Total Data Exfiltration Volume: ~161 MB of Secret Project Documents Across Two USB Devices** (f_024135e6, high, confirmed): Summary of all exfiltrated data identified across both removable media devices:

**RM1 Active Files (5 documents, ~74.4 MB):**
- [secret_project]_design_concept.ppt: 1,810,432 bytes (1.7 MB)
- [secret_project]_detailed_design.pptx: 16,381,123 bytes (15.6 MB)
- [secret_project]_revised_points.ppt: 14,547,968 bytes (13.9 MB)
- [secret_project]_detailed_proposal.docx: 35,226,880 bytes (33.6 MB)
- [secret_project]_proposal.docx: 6,484,502 bytes (6.2 MB)

**RM2 Disguised/Deleted Files (17 documents, ~87.3 MB):**
Design (2): 30,929,091 bytes (29.5 MB)
Pricing (4): 21,887,309 bytes (20.9 MB)
Progress (3): 4,526,017 bytes (4.3 MB)
Proposal (2): 41,711,382 bytes (39.8 MB) - includes RM1 duplicates
Technical (6): 5,079,142 bytes (4.8 MB)

**RM2 Cover Images (21 deleted genuine images, ~77.2 MB)**

**Combined unique document data: ~131 MB** (accounting for 4 duplicated files between RM1/RM2)

The document categories span all project work streams: design, pricing, progress tracking, proposals, and technical documentation. The "diary" naming pattern in the technical directory (diary_#1d, #1p, #2d, #2p, #3d, #3p) suggests weekly or bi-weekly deliverable reports, with 'd' and 'p' suffixes possibly representing different document types (document/presentation) covering 3 reporting periods.

The modification dates range from 2014-12-01 to 2015-01-23, suggesting the exfiltrated data covers approximately 2 months of project activity. The exfiltration occurred in two phases: RM1 copy on 2015-02-15 and RM2 copy on 2015-03-24.

**Affected Systems:** tsk.filelist, tsk.masquerade, tsk.timeline



### 6. [HIGH] PC User "informant" Accessed Secret Project Documents Prior to USB Copy

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:34:41 to 2015-03-24T10:00:18 |
| **Sources** | ez.mft, tsk.filelist |
| **Evidence Refs** | tc_805b185c, tc_98a99946, tc_623895d5 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The PC image (cfreds_2015_data_leakage_pc.E01) contains a user profile \"informant\" (SID S-1-5-21-2425377081-3129163575-2985601102-1000) whose Recent Documents folder contains LNK shortcut files for the secret project documents:

1. [secret_project]_design_concept.lnk - created 2015-03-23T18:38:21 (MFT entry 71140, parent inode 542 = .\Users\informant\AppData\Roaming\Microsoft\Windows\Recent)
2. [secret_project]_final_meeting.pptx.lnk - created 2015-03-23T20:27:33 (MFT entry 4166, same Recent directory)

The "informant" user profile was created on 2015-03-22T14:34:41 (NTUSER.DAT creation timestamp). The user's name "informant" itself is suggestive of the role in data leakage.

Additionally, a second user account "admin11" exists on the PC with Google Chrome browser data, indicating the PC was shared or administered.

The timeline shows:
- User "informant" account created: 2015-03-22T14:34:41
- Secret project documents accessed from PC: 2015-03-23T18:38:21 to 2015-03-23T20:27:33
- RM2 disguised files created (batch copy): 2015-03-24T09:59:27 to 2015-03-24T10:00:18
- Temp Word file created/deleted on RM1: 2015-03-23T14:37:52 to 2015-03-23T14:38:46

**Counter-analysis note (RM1 timeline):** The RM1 USB files have modification dates of Dec 2014 – Jan 2015, and RM1 directory timestamps indicate files were placed on 2015-02-15. Since this PC was not created until 2015-03-22, the RM1 copy was performed from a DIFFERENT computer or workstation. The PC evidence connects the informant to the RM2/RM3 copies (March 24) but not directly to the original RM1 copy. The RM1 to RM2/RM3 link is established through exact file size matches and EXIF hash correlation, confirming the same documents across all media.

**Counter-analysis note (1-hour timestamp offset):** The PC's timezone is Eastern Standard Time (ActiveTimeBias=240, EDT active). RM1 and RM2 file modification times differ by exactly 1 hour (e.g., RM1: 2014-12-16T11:10:26 vs RM2: 2014-12-16T12:10:26). Since FAT filesystems store local time, the offset is explained by the RM1 files having been written in a different timezone context (likely from the different source computer), not a discrepancy in the data.



### 7. [HIGH] Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Removable Media (RM1, RM2, RM3)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-04T11:24:50 to 2015-01-23T15:47:10 |
| **Sources** | bulk.email, bulk.url_services, bulk.exif, bulk.rfc822 |
| **Evidence Refs** | tc_b71bcf8a, tc_e90b0ec4, tc_86aef7b2 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/) |


Document metadata carved through bulk extractor analysis reveals the secret project documents contain NASA/JPL Mars exploration content across ALL three removable media devices. Multiple independent artifact types confirm identical content on each medium.

**Email addresses embedded in documents (identical across RM1, RM2, RM3):**
- David.Beaty@jpl.nasa.gov (Jet Propulsion Laboratory)
- Karen.L.Buxbaum@jpl.nasa.gov (Jet Propulsion Laboratory)
- mmeyer@mail.hq.nasa.gov (NASA Headquarters)
- Eric_P._Lauer@omb.eop.gov (Office of Management and Budget)
- mmun@loc.gov (Library of Congress)
- th276a@nih.gov (National Institutes of Health)
- wayne.longman@att.net (external contact)

**URLs found in documents (matching counts across RM2 and RM3):**
- mepag.jpl.nasa.gov (Mars Exploration Program Analysis Group)
- ltpwww.gsfc.nasa.gov (NASA Goddard Space Flight Center)
- nodis3.gsfc.nasa.gov, hq.nasa.gov, nen.nasa.gov, msds.ksc.nasa.gov
- whitehouse.gov, sc.doe.gov (Department of Energy)
- hdl.loc.gov (Library of Congress)
- infotrek.er.usgs.gov (USGS)
- assist.daps.dla.mil (Defense Logistics Agency)
- dx.doi.org academic paper DOI references

**EXIF data in embedded images (matched across all 3 devices by SHA1 hash):**
- Images created with Kodak DC260 camera (2003-2006)
- Images processed with Adobe Photoshop CS/CS2

The URL histogram counts match nearly identically between RM2 and RM3 (e.g., schemas.openxmlformats.org n=3403 on both), confirming byte-identical document content. The document content spans NASA/JPL, OMB, Library of Congress, NIH, DOE, USGS, and military domains — all U.S. government work products consistent with the user's NIST affiliation (iaman.informant@nist.gov).



### 8. [HIGH] PC Search History Reveals Extensive Insider Threat Research - Data Leakage Methods, Anti-Forensics, and Evidence Destruction

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T14:59:57 to 2015-03-23T15:30:07 |
| **Sources** | bulk.url_searches |
| **Evidence Refs** | tc_4b67f591 |
| **ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1070](https://attack.mitre.org/techniques/T1070/), [T1036](https://attack.mitre.org/techniques/T1036/) |


Bulk extractor analysis of the PC image (cfreds_2015_data_leakage_pc.E01) reveals extensive web search activity demonstrating deliberate research into data exfiltration methods, anti-forensic techniques, and evidence destruction. Key searches grouped by category:

**Data Leakage Planning:**
- "information leakage cases" (47+ hits across multiple sessions)
- "how to leak a secret" (6 hits)
- "leaking confidential information" (2 hits)
- "data leakage methods" (1 hit)
- "intellectual property theft" (6 hits)
- "file sharing and tethering" (491 hits - most frequent search)
- Visited: http://www.mediapost.com/...google-to-settle-data-leakage-case-for-85-mill.html (Google data leakage case)
- Visited: emirates247.com/business/technology/top-5-sources-leaking-personal-data

**Anti-Forensic Techniques:**
- "anti-forensic tools" (85 hits)
- "anti-forensics" (multiple sessions)
- "ccleaner" (65 hits)
- "eraser" (51 hits)
- "system cleaner" (5+ hits)
- "how to delete data" (5+ hits)
- Downloaded DEFCON 20 Anti-Forensics PDF: https://defcon.org/images/defcon-20/dc-20-presentations/Perklin/DEFCON-20-Perklin-AntiForensics.pdf
- "DLP DRM" (90 hits - researching how to bypass data loss prevention)

**Data Transfer Methods:**
- "cd burning method" and "cd burning method in windows" (64/53 hits)
- "external device and forensics" (65 hits)
- "cloud storage" (6 hits)
- "google drive" (10 hits)
- "apple icloud" (1 hit)
- "security checkpoint cd-r" (1 hit - researching security screening of physical media)

**Forensic Countermeasures (awareness of investigation):**
- "digital forensics" (multiple sessions)
- "e-mail investigation" (88 hits)
- "Forensic Email Investigation" (78 hits)
- "what is windows system artifacts" (79 hits)
- "investigation on windows machine" (64 hits)
- "windows event logs" (61 hits)
- "data recovery tools" (4+ hits)
- "how to recover data" (2+ hits)
- Visited FBI Intellectual Property Rights investigation page: http://www.fbi.gov/about-us/investigate/white_collar/ipr/ipr

The search progression shows the user started with "information leakage cases" as a starting search, then branched into specific leakage methods (USB, CD, cloud), anti-forensic tools (CCleaner, Eraser), DLP bypass techniques, and forensic awareness topics. The user also visited the FBI's intellectual property theft investigation page, indicating awareness of potential legal consequences, and downloaded a DEFCON presentation specifically about anti-forensics techniques. This represents systematic preparation for an insider data theft operation.

**Counter-analysis note (NIST security research):** The investigation question asked whether these searches could reflect legitimate NIST cybersecurity research duties. This hypothesis was investigated and rejected for the following reasons: (1) No NIST cybersecurity publications, research papers, or institutional research directories were found on the PC; (2) the search terms are operational/practical ("how to leak a secret," "how to delete data," "security checkpoint cd-r") rather than academic/analytical; (3) the searches directly correlate with actions subsequently taken (CCleaner and Eraser were downloaded, installed, and executed; CDs were burned; USB devices were used for data transfer); (4) a NIST researcher studying anti-forensics would not also be searching for "information leakage cases" and visiting the FBI IP theft page in the same session; (5) the user's name "Iaman Informant" and resignation letter creation in the same timeframe eliminate legitimate research as a plausible explanation.

**Note on hit counts:** Bulk extractor URL hit counts represent carved URL instances from disk, not necessarily individual search sessions. Multiple hits for the same query may reflect page reloads, cached copies, or multiple search result pages. However, the diversity and specificity of the search topics (not just repeated queries) confirms deliberate, multi-topic research.



### 9. [HIGH] All Files on RM2 Are Deleted — Device Was Wiped After Use

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T15:51:47 to 2015-03-24T17:02:36 |
| **Sources** | tsk.filelist, bulk.zip_carved |
| **Evidence Refs** | tc_da48f35a, tc_ae58b7ab, tc_ced43b37 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Every file on the RM2 removable media device is marked as deleted in the filesystem. The file listing (51 entries total) shows:
- Volume label entry: "IAMAN $_@" (the only non-deleted metadata entry)
- System entries: $MBR, $FAT1, $FAT2, $OrphanFiles
- ALL user files are in $OrphanFiles and marked with the deletion flag (*)
- This includes the 17 masqueraded Office documents in subdirectories
- 22 personal image files in the root level
- 1 desktop.ini file

The fact that ALL files are deleted indicates the device was intentionally wiped or formatted after the data exfiltration operation. However, the file entries and directory structures are still recoverable from the FAT filesystem metadata, and bulk_extractor was able to carve significant content from unallocated space including document metadata, email addresses, and OOXML structures.

The zip_carved source from RM2 contains 5,221 carved entries from unallocated space, including Office document components (docProps, word/, ppt/, xl/ directories) confirming the deleted files' contents are at least partially recoverable. The OOXML ZIP structures within the carved data confirm the presence of Word (docx), PowerPoint (pptx), and Excel (xlsx) documents matching the masquerade detection results.



### 10. [HIGH] Multi-Session Disc Burning Shows Concealment Strategy — Files Overwritten with Cover Images

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T20:57:03 |
| **Sources** | optical.listing |
| **Evidence Refs** | tc_aa9b4e93 |
| **ATT&CK** | [T1070](https://attack.mitre.org/techniques/T1070/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The RM3 optical disc has 9 VAT generations (sessions) revealing a deliberate concealment strategy where the exfiltrated files were burned and then overwritten with innocuous cover images in subsequent sessions.

**Session analysis:**
- Session -7 (earliest recoverable): Files in abbreviated directory "de/" (design) — winter_storm.amr, winter_whether_advisory.zip
- Session -6: Files in abbreviated "pd/" (pricing decision) — 4 files
- Session -5: Files in abbreviated "prog/" (progress) — 3 files
- Session -4: Files in abbreviated "prop/" (proposal) — 2 files
- Session -3: Files in abbreviated "tr/" (technical review) — 6 diary files
- Sessions -3 through -7 also contain files with FULL directory names (design, pricing decision, progress, proposal, technical review) — same files, same sizes
- Session -1: Abbreviated directory names with all 17 files
- Session 0 (final/current): Only 3 Windows sample images (Koala.jpg, Penguins.jpg, Tulips.jpg) remain active; all previous directories and files show as "deleted"

The disc was burned in phases:
1. First, the masqueraded documents were burned in directories with abbreviated names (likely first attempt)
2. Then the same files were burned again with full directory names (second attempt or renaming)
3. Finally, the masqueraded files were overwritten by burning 3 innocuous Windows sample photos as the active session

This multi-session approach on a write-once UDF disc means the old data persists in earlier sessions even though the final session shows only the cover images. The suspect likely believed overwriting the disc with cover images would hide the previously burned sensitive documents, not realizing UDF VAT sessions are forensically recoverable.



### 11. [HIGH] PC Registry and Timeline Prove User "informant" Burned Data to CD on March 24, 2015 Evening

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:44:18 to 2015-03-24T21:01:14 |
| **Sources** | registry.ntuser.informant, tsk.timeline, optical.listing |
| **Evidence Refs** | tc_ce238570, tc_0083fa0d, tc_aa9b4e93 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


The PC image (cfreds_2015_data_leakage_pc.E01) provides corroborating evidence that user "informant" burned the exfiltrated data to the RM3 optical disc on the evening of March 24, 2015.

**RecentDocs Registry Evidence (LastWrite: 2015-03-25T15:29:08Z):**
The user's RecentDocs key contains entries proving disc interaction:
- "BD-RE Drive (D:) IAMAN CD" (MRU position 13 — accessed disc labeled "IAMAN CD")
- "BD-RE Drive (D:)" (MRU position 10 — accessed the optical drive itself)
- "Koala.jpg" (MRU position 9)
- "Penguins.jpg" (MRU position 12)
- "Tulips.jpg" (MRU position 11)
- "winter_whether_advisory.zip" (MRU position 7 — accessed the masqueraded PPTX file)

The .jpg MRU (LastWrite: 2015-03-24T21:01:14Z) and Folder MRU (LastWrite: 2015-03-24T21:01:14Z) confirm the exact time of disc access.

**PC Filesystem Timeline Correlation:**
- 20:44:18Z — winter_whether_advisory.zip.lnk created in informant's Recent folder (accessed masqueraded file)
- 20:47:22Z — Koala.jpg.lnk born; "CD Drive.lnk" born (disc drive opened)
- 20:47:30Z — Tulips.jpg.lnk born; CD Drive.lnk modified (second file accessed)
- 20:53:08Z — RUNDLL32.EXE-FE9FC6E1.pf created (potentially related to CD burn operation)
- 21:01:10Z — Penguins.jpg.lnk born (third cover image accessed)
- 21:01:12-14Z — Koala.jpg.lnk, Tulips.jpg.lnk, CD Drive (2).lnk all modified (burn verification)

**Disc timestamps match PC timeline:**
Disc files created at 20:54:16-20:57:03Z, which falls perfectly within the 20:44-21:01 window of disc-related activity on the PC.

**Optical drive type:** BD-RE (Blu-ray Rewritable) drive mapped as D: drive, used for burning a UDF write-once disc.

**Volume label "IAMAN CD"** matches the user's email username "iaman" (iaman.informant@nist.gov) and the RM2 volume label pattern "IAMAN $_@", confirming all three devices belong to the same user.



### 12. [HIGH] EXIF Hash-Level Confirmation: Embedded Document Images Match Across RM1, RM2, and RM3

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T20:57:03 |
| **Sources** | bulk.exif |
| **Evidence Refs** | tc_2d2795e0, tc_d0c1aa30 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Bulk extractor EXIF carving from the RM3 optical disc reveals embedded image SHA1 hashes that match exactly across all three removable media devices, providing hash-level confirmation that RM3 contains copies of the same secret project documents found on RM1 and RM2.

**All matching SHA1 hashes across RM1/RM2/RM3:**

| SHA1 Hash | RM1 Offset | RM2 Offset | RM3 Offset |
|-----------|------------|------------|------------|
| a41bab08fd5f7a4329a0362a16221a8e358b9332 | 70600277 | 98612821 | 95018581 |
| 8068fd29eabe2bb25a492af6803fea66405261a1 | 70642049 | 98654593 | 95060353 |
| 872cf02906a33a512f6aa3bb50eccd93beed4a9a | 71127352 | 99139896 | 95545656 |
| 5e2d5503a962c88167b87d342c6da3fccadc720b | 71205400 | 99217944 | 95623704 |
| f197df39f466e97409c6c291b7c04c5ccccb3751 | 71254761 | 99267305 | 95673065 |
| 51d8158c1f8391b1d924d6dcd9932862cd29d73a | 71370265 | 99382809 | 95788569 |
| 7fe32ccab8ec5d785e7e85a1573865ff51caf6ec | 71417563 | 99430107 | 95835867 |
| 4022cfed1fa2589e00852b8b4a30b89390e0deaa | 71472901 | 99485445 | 95891205 |
| ab363f36287d93dc62f4672ebce65925df783197 | 71543597 | 99556141 | 95961901 |
| aab7ebb56ec75ae3da1534c300ac65637f96b9a9 | 72892692 | 100905236 | 97310996 |
| 14a4ca796f8db517fdd0a88cce713da0501932d5 | 75229363 | 103241907 | 99647667 |

All 11 images were processed with "Adobe Photoshop CS Macintosh" on 2006-03-21, confirming they are embedded graphics within the secret project documents.

The RM3 disc also contains the same Kodak DC260 camera EXIF data (2003:09:24 and 2003:12:10 photos) found on RM1 and RM2, further confirming identical document content across all three media.

Additionally, 3 new EXIF entries unique to the RM3 disc's cover images have Artist="Corbis" and "Microsoft Corporation" — confirming these are the standard Windows 7 sample photos (Koala.jpg, Penguins.jpg, Tulips.jpg) that are not part of the exfiltrated documents.



### 13. [HIGH] Local "S data" Staging Directory on Desktop Used for Data Collection Before USB/CD Transfer

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:47:58 to 2015-03-24T19:52:06 |
| **Sources** | registry.usrclass.informant |
| **Evidence Refs** | tc_85216d97, tc_cf86e04b |
| **ATT&CK** | [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1005](https://attack.mitre.org/techniques/T1005/) |


Shellbag analysis of the informant's UsrClass.dat reveals the user created a staging directory called "S data" on the Desktop to organize stolen Secret Project data before copying it to removable media.

**Shellbag entries for S data directory (all timestamps 2015-03-24 13:47-13:48):**
- S data\Secret Project Data\Secret Project Data\final (MFT ref 71686/14, accessed 2015-03-24 13:47:58)
- S data\Secret Project Data\Secret Project Data\pricing decision (MFT ref 71735/4, accessed 2015-03-24 13:48:00)
- S data\Secret Project Data\final (MFT ref 71686/14, accessed 2015-03-24 13:47:58)
- S data\Secret Project Data\pricing decision (MFT ref 71735/4, accessed 2015-03-24 13:48:00)
- S data\Secret Project Data\progress (MFT ref 73368/7, accessed 2015-03-24 13:48:00)
- S data\Secret Project Data\technical review (MFT ref 74299/9, accessed 2015-03-24 13:48:00)

**Data flow timeline on 2015-03-24:**
1. 13:21:10 - USB drive (E:) mounted via MountedDevices
2. 13:38:31 - User browses E:\RM#1\Secret Project Data (RM1 USB)
3. 13:40-13:57 - User accesses "S data" staging directory on Desktop (shellbags)
4. 13:47-13:48 - Browsing "S data" subdirectories (final, pricing decision, progress, technical review)
5. 09:54-10:00 - Masqueraded files created on RM2 (earlier same day - possibly timezone offset)
6. 20:54-20:57 - Same masqueraded files burned to RM3 optical disc

**Additional Desktop shellbag entries related to staging:**
- "New folder" and "temp" on Desktop share the same MFT ref (74402/9), indicating the folder was renamed from "New folder" to "temp" at 2015-03-24 19:52:06

**Related activity:**
- Libraries\Sample Pictures accessed at 2015-03-24 14:44:23
- Libraries\Sample Music accessed at 2015-03-24 19:52:49
- Libraries\Sample Videos accessed at 2015-03-24 19:52:58

The Sample Pictures access coincides with the timing of Windows sample photos (Koala.jpg, Penguins.jpg, Tulips.jpg) later burned as cover content to the optical disc at 20:57. The user was also collecting cover images from the RM2 device (22 deleted personal photos with birth timestamps on 2015-03-23).

The "S data" directory name appears to be an abbreviation for "Secret data" or "Staged data", and its complete absence from the MFT suggests it was successfully deleted via the anti-forensic tools (CCleaner/Eraser) used on 2015-03-25.



### 14. [HIGH] Resignation Letter Created on Final Day Corroborates Insider Threat Departing Organization

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T18:48:40 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant, tsk.timeline, ez.mft |
| **Evidence Refs** | tc_8f67c2bd, tc_5c553f29 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


User "informant" (Iaman Informant, iaman@NIST.GOV) created a resignation letter on March 24–25, 2015, the same days as the final exfiltration activities. This is the strongest behavioral corroboration of a departing insider threat.

**Evidence from Multiple Independent Sources:**

1. RecentDocs Registry (registry.ntuser.informant):
   - "Resignation_Letter_(Iaman_Informant).docx" — MRU position 8 (most recently accessed #1)
   - "Resignation_Letter_(Iaman_Informant).xps" — MRU position 14 (second most recently accessed)
   - LastWrite Time: 2015-03-25T15:29:08

2. OpenSavePidlMRU (registry.ntuser.informant):
   - docx version: saved/opened via WINWORD.EXE at 2015-03-24T18:48:40
   - xps version: saved/opened at 2015-03-25T15:28:33

3. UserAssist (registry.ntuser.informant):
   - WINWORD.EXE: 4 executions, last at 2015-03-25T15:24:48
   - xpsrchvw.exe: 1 execution at 2015-03-25T15:28:47 (XPS viewer to read the printed/exported letter)

4. TSK Timeline (tsk.timeline):
   - Resignation_Letter_(Iaman_Informant).xps.lnk created at 2015-03-25T15:28:33 (LNK shortcut in Recent)
   - OPC temp file DDT.mqdju9hr7njt3dazsys5pbced.tmp created/deleted at 2015-03-25T15:28:48 (XPS document packaging)

5. PC Timeline Context:
   - Document first created as .docx on Mar 24 at 18:48:40
   - Document exported to .xps format on Mar 25 at 15:28:33
   - This was the LAST documented activity on the PC before image acquisition

**Chronological Significance:**
The resignation letter was created between the data exfiltration (Mar 24) and the anti-forensic cleanup (Mar 25). The final activity sequence on March 25:
- 14:47–14:50: Download anti-forensic tools (Eraser, CCleaner)
- 15:12: Run Eraser
- 15:15: Run CCleaner
- 15:21: Run Google Drive
- 15:24–15:28: Create/edit Resignation Letter, export to XPS
- 15:29: Final RecentDocs entry

The user's real name "Iaman Informant" in the filename directly identifies the insider.



### 15. [MEDIUM] Deleted Cover Images on RM2 Suggest Anti-Forensic Concealment Strategy

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | tsk.filelist, bulk.rfc822 |
| **Evidence Refs** | tc_7ba915df, tc_2691ed37 |
| **ATT&CK** | [T1036.007](https://attack.mitre.org/techniques/T1036/007/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


In addition to the 17 disguised Office documents, RM2 contains 21 deleted legitimate image files in the root $OrphanFiles directory. These appear to be genuine images that served as visual "cover" content on the USB device:

**Deleted image files (all in $OrphanFiles/):**
amalfi.bmp, BAMBOO~1.GIF, barn.gif, blini.gif, boudicca.bmp, cactus.png, cave.png, CUTTY-~1.JPG, eggs.gif, FORSYT~1.PNG, injera.gif, JACK-O~1.TIF, jump.jpg, leaf.jpg, oak-snow.jpg, orchid.png, PIAZZA~1.JPG, pisa.JPG, SPQR.JPG, STONEH~1.JPG, tapas.gif, tomatoes.gif, wat.gif

Also present: desktop.ini (deleted)

The RFC822 headers carved from RM2 contain Library of Congress catalog-style entries describing historical portraits and prints, suggesting these images may have been sourced from or related to the Library of Congress digital collections.

These images are distinct from the masqueraded files (which are in subdirectories). The likely concealment strategy: the USB device appeared to contain a collection of stock/travel/food images with innocuous file names, while the actual sensitive data was hidden in subdirectories with disguised extensions. The directory names (design, pricing, progress, proposal, technical) could plausibly be related to an innocent project if only directory names were visible.

All files are deleted, indicating the entire USB content was wiped after the data was transferred. The tsk.masquerade source confirms none of these root-level image files triggered extension mismatches - they are genuine images.



### 16. [MEDIUM] Google Account Authentication Confirms Webmail Access: "informant@accounts.google.com" Cookie Carved from PC

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-25T15:22:08 to 2015-03-25T15:24:51 |
| **Sources** | bulk.email, ez.mft, bulk.url |
| **Evidence Refs** | tc_377301da, tc_e9bd8517, tc_a41c439e |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |


Bulk extractor analysis of the PC image reveals evidence of Google account authentication and webmail service access, providing another potential data exfiltration channel.

**Google Account Authentication:**
- Cookie carved at disk offset 2664903014: "Cookie: informant@accounts.google.com/" — proves the user logged into Google services with a Google account named "informant"
- IE Temporary Internet Files: AccountChooser[1].htm cached at 2015-03-25 15:22:08 (MFT inode 73739) — Google's account selection page, accessed on the final day
- OAuth URL: https://accounts.google.com/o/oauth2/postmessageRelay?parent=https%3A%2F%2Fwww.google.com — OAuth authentication flow
- emailhrd[1].htm cached at 2015-03-25 15:24:51 (MFT inode 72004) — email-related HTML page cached in IE, accessed minutes before shutdown

**Gmail and Google Services Access:**
- https://mail.google.com/mail/ca/#settings — Gmail settings page accessed
- https://mail.google.com/mail/?view=cm — Gmail compose link found
- https://mail.google.com/mail/?tab=wm — Gmail webmail tab link

**Other Webmail Service References:**
- https://mail.yahoo.com — Yahoo Mail link reference
- https://hotmailproxy.msn.com — Hotmail/MSN proxy reference
- https://outlook.office365.com/EWS/Exchange.asmx — Exchange Web Services (organization's email)
- https://outlook.office365.com/OAB/ — Offline Address Book (Exchange autodiscover)

**Timeline of Google activity on final day (2015-03-25):**
- 15:12:28 — Eraser.exe executed (anti-forensic tool)
- 15:15:50 — CCleaner64.exe executed (anti-forensic tool)
- 15:20:59 — Google Drive folder accessed (shellbags)
- 15:21:30 — googledrivesync.exe executed (UserAssist)
- 15:22:08 — AccountChooser[1].htm cached (Google account sign-in)
- 15:24:51 — emailhrd[1].htm cached (email-related page)
- 15:28:33 — Resignation letter XPS version created
- 15:29:08 — Resignation letter DOCX last accessed

The Google account login occurred AFTER running anti-forensic tools and AFTER syncing Google Drive, suggesting the user may have been verifying that their cloud-uploaded data was intact or accessing webmail to send the resignation letter, all in the final minutes before system shutdown.



### 17. [MEDIUM] PC Recycle Bin Contains Deleted Windows Sample Photo — Preparation for Optical Disc Cover Content

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T19:51:47 to 2015-03-25T15:15:50 |
| **Sources** | ez.mft, tsk.filelist |
| **Evidence Refs** | tc_e56714b8, tc_1b933c4e, tc_2c7a6d88 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The PC's Recycle Bin (under the informant's SID S-1-5-21-2425377081-3129163575-2985601102-1000) contains two deleted items that provide context for the optical disc cover operation:

**Recycle Bin Item 1: $I40295N / $R40295N**
- $I40295N metadata file: 544 bytes, created 2015-03-24 19:51:47 (MFT inode 74313)
- $R40295N content file: Not found in MFT (purged by anti-forensic tools)
- Timing: Deleted at 19:51:47, just before the user started browsing Sample Music (19:52:49) and Sample Videos (19:52:58) in shellbags

**Recycle Bin Item 2: $I508CBB.jpg / $R508CBB.jpg**
- $I508CBB.jpg metadata file: 544 bytes, created 2015-03-24 20:11:42 (MFT inode 74760)
- $R508CBB.jpg content file: 0 bytes (content purged), creation time 2009-07-14 05:32:31 — this is the default timestamp for Windows 7 Sample Pictures (Koala.jpg=780831 bytes, Penguins.jpg=777835 bytes, Tulips.jpg=620888 bytes, etc.)
- Timing: Deleted at 20:11:42, approximately 5 minutes before the optical disc burn began at 20:54:16

**Context:**
The deleted photo's original timestamp (2009-07-14 05:32:31) matches the Windows 7 sample photos exactly. On the RM3 optical disc, Koala.jpg, Penguins.jpg, and Tulips.jpg (all with modification dates of 2009-07-14 05:32:31) were burned as cover content in the final disc session. The Recycle Bin deletion suggests the user accessed and then discarded a sample photo as part of preparing the cover content for the disc burn operation.

**Browser History Wiped:**
No browser history databases (Chrome, IE, Firefox) were recoverable from the PC. The parse_browser_history tool found no databases. This is consistent with CCleaner execution at 2015-03-25 15:15:50, which was specifically designed to clear browser history, cookies, and cache. However, bulk extractor was able to carve URL and search history from unallocated space and IE Temporary Internet Files, recovering the research activity documented in other findings.



### 18. [MEDIUM] Google Drive and iCloud Installed and Executed — Cloud Exfiltration Channels Prepared But No Confirmed Data Transfer

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T19:56:33 to 2015-03-25T15:21:30 |
| **Sources** | ez.shimcache, registry.ntuser.informant, bulk.url, bulk.url_searches |
| **Evidence Refs** | tc_6076ddf1, tc_8f67c2bd, tc_2be5eee8 |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1567](https://attack.mitre.org/techniques/T1567/) |


The user "informant" downloaded, installed, and executed both Google Drive and iCloud applications, establishing potential cloud exfiltration channels. However, no direct evidence of document upload through these services was found.

**Google Drive:**
- Shimcache: C:\Program Files (x86)\Google\Drive\googledrivesync.exe, Modified 2015-02-19T18:24:24, Executed=Yes (entry #20)
- Shimcache: googledrivesync64.dll loaded (entry #13)
- Shimcache: contextmenu64.dll loaded (entry #67) — context menu integration
- UserAssist: googledrivesync.exe run 1 time at 2015-03-25T15:21:30
- UserAssist shortcut: Google Drive.lnk launched at 2015-03-25T15:21:30
- Downloaded: C:\Users\informant\Downloads\googledrivesync.exe at 2015-03-23T19:56:33
- bulk.url: Download URL http://r18---sn-p5qlsne7.c.pack.google.com/edgedl/drive/1.20.8672.3137/gsync.msi from IP 129.6.58.42

**Apple iCloud:**
- Shimcache: C:\Program Files (x86)\Common Files\Apple\Internet Services\iCloud.exe, Modified 2014-12-02T02:26:10, Executed=Yes (entry #189)
- Shimcache: ApplePhotoStreams.exe executed (entry #183)
- Downloaded: C:\Users\informant\Downloads\icloudsetup.exe at 2015-03-23T19:56:53
- UserAssist (no timestamp entries): iCloud.exe and icloudsetup.exe listed
- Apple Software Update also executed

**Web Search Context:**
- "cloud storage" (6 hits), "google drive" (10 hits), "apple icloud" (1 hit) in bulk.url_searches
- Wikipedia article on Cloud_storage visited via Google search

**Counter-analysis consideration (personal use):** It is theoretically possible that Google Drive and iCloud were installed for personal use unrelated to exfiltration. However, the following factors weigh against this interpretation: (1) Google Drive was executed on the final day of activity (March 25) at 15:21:30, AFTER anti-forensic tools were run at 15:12-15:15 — this sequencing suggests the user was checking or using the cloud service as part of their departure workflow, not routine personal use; (2) the IP 129.6.58.42 in the download URL is confirmed as a NIST IP address (ASN AS49), confirming the download occurred from the NIST network; (3) the search history specifically includes "cloud storage" and data transfer methods in the same session as anti-forensic and data leakage research; (4) CCleaner execution afterward may have removed evidence of actual file uploads. The lack of confirmed data transfer prevents elevation above medium severity, but the contextual timing is inconsistent with innocent personal use.



### 19. [INFO] USB Device Identification - exFAT "Authorized USB" with Volume Serial 5c75-4d3e

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.fsstat, hashdeep.hashes, tsk.partitions |
| **Evidence Refs** | tc_844d930d, tc_ce5935a8, tc_29e101e0 |


The primary removable media device (RM1) has the following identifying characteristics:

**Filesystem:** exFAT v1.0
**Volume Label:** "Authorized USB" (from root directory)
**Volume Serial Number:** 5c75-4d3e
**Partition Type:** EXFAT (from MBR)
**Sector Size:** 512 bytes
**Cluster Size:** 32,768 bytes (32 KB)
**Total Sectors:** 7,821,280 (sector range 0 - 7,821,279)
**Cluster Range:** 2 - 122,190
**Estimated Capacity:** ~3.7 GB

**Partition Layout:**
- Partition starts at sector 32
- FAT 1: sectors 128 - 1,087
- Data Area: sectors 1,152 - 7,821,279
- Root Directory: sectors 1,280 - 1,343

The volume label "Authorized USB" suggests this device may have been presented as an authorized/approved USB device, potentially to bypass physical security controls or DLP policies. The device uses exFAT which is compatible with both Windows and macOS systems.

**RM1 Image Hash:**
- MD5: 7cd7bc148d3a1e5f329cb3580d4d4f8f
- SHA256: a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121
- File size: 78,186,742 bytes (74.5 MB)

**RM2 Identification:**
- Volume Label: "IAMAN $_@" (appears corrupted/garbled)
- FAT filesystem
- Contains only deleted files in orphan directories



### 20. [INFO] Removable Media Identification: FAT Filesystem with "IAMAN" Volume Label Linked to User Account

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.fsstat, tsk.partitions, hashdeep.hashes, bulk.email, tsk.filelist |
| **Evidence Refs** | tc_7ce06c16, tc_de4b58f2, tc_67f1d4e9, tc_748debe0 |


The removable media device (cfreds_2015_data_leakage_rm2.E01) is formatted with a FAT filesystem containing two FAT copies ($FAT1 and $FAT2). The volume label is "IAMAN $_@".

This volume label directly correlates to the user identity found on the companion PC image (cfreds_2015_data_leakage_pc.E01):
- PC user account: "informant"
- Outlook email profile: iaman.informant@nist.gov.ost
- Email address: iaman@NIST.GOV / iaman.informant@nist.gov

The "IAMAN" prefix in the volume label matches the email account username, strongly suggesting this is a personal removable device belonging to the user "iaman" at NIST. The companion removable device RM1 uses exFAT filesystem with volume label "Authorized USB" (serial 5c75-4d3e), suggesting it may be a company-issued device, whereas RM2 appears to be a personal device.

Image hashes:
- RM2: MD5=6cfbfdb14e0a504684a338b87362d753, SHA256=25215f9bcb51ceee9147886ed3f5c13ef148de634fc5114491e0f8dad8b15696
- RM1: MD5=7cd7bc148d3a1e5f329cb3580d4d4f8f, SHA256=a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121



### 21. [INFO] Application Execution Summary: Office Suite, Email, Browser, and Data Transfer Tools Used for Exfiltration

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:28:47 |
| **Sources** | registry.ntuser.informant, registry.system |
| **Evidence Refs** | tc_5213e0fa, tc_92e3ff15 |
| **ATT&CK** | [T1059.003](https://attack.mitre.org/techniques/T1059/003/), [T1005](https://attack.mitre.org/techniques/T1005/) |


Multiple execution artifact sources (UserAssist, ShimCache, MFT) document the informant's use of applications relevant to the data leakage operation. The complete execution profile shows systematic use of document viewing, email, browser, and data management tools.

**Office Applications (ShimCache + UserAssist):**
- WINWORD.EXE (Word): 4 executions, last 2015-03-25 15:24:48 - opened secret project docs + resignation letter
- POWERPNT.EXE (PowerPoint): 2 executions, last 2015-03-23 20:27:33 - opened .pptx files
- EXCEL.EXE: 1 execution, 2015-03-23 20:26:50 - opened pricing spreadsheets
- OUTLOOK.EXE: 5 executions, last 2015-03-25 14:41:03 - email client (iaman.informant@nist.gov)

**Browsers:**
- Chrome: 7 executions via UserAssist, Chrome 41.0.2272.101 installed
- Internet Explorer: 5 executions via UserAssist
- Browser searches included data leakage methods, anti-forensics, cloud storage, CD burning

**Cloud/Data Transfer Tools (from ShimCache with "Executed" flag):**
- googledrivesync.exe: Google Drive sync client installed and run
- icloudsetup.exe: iCloud installer downloaded and executed
- iCloud.exe: Apple iCloud client executed
- ApplePhotoStreams.exe: Apple photo sync service executed

**Anti-Forensic/Cleanup Tools:**
- CCleaner64.exe: System cleaning tool (1 execution 2015-03-25 15:15:50)
- Eraser.exe: Secure file deletion tool (1 execution 2015-03-25 15:12:28)

**System/Command Tools:**
- cmd.exe: 4 executions (2015-03-23 20:10:19) - command line access
- WScript.exe: Script host executed (potential automation)
- taskmgr.exe: Task Manager used

**RecentDocs accessed files confirm document access pattern:**
- [secret_project]_proposal.docx
- [secret_project]_design_concept.ppt
- (secret_project)_pricing_decision.xlsx
- [secret_project]_final_meeting.pptx
- winter_whether_advisory.zip (masqueraded PPTX file from RM2)
- Resignation_Letter_(Iaman_Informant).docx/.xps

**Explorer Search (WordWheelQuery):**
- User searched for "secret" in Windows Explorer (2015-03-23 18:40:17)



### 22. [INFO] Microsoft Outlook Email Client Used with iaman.informant@nist.gov Account

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:48:40 to 2015-03-25T14:41:03 |
| **Sources** | registry.ntuser.informant, bulk.domain, tsk.filelist |
| **Evidence Refs** | tc_5213e0fa, tc_e1b4605d, tc_36d2414b |


Outlook 2013 (Office 15) was actively used by the informant with an email account tied to NIST (National Institute of Standards and Technology).

**Email account identification:**
- Bulk extractor carved from PC disk: "iaman.informant@nist.gov" at multiple disk offsets
- Bulk extractor carved: "informant@nist.gov" (shortened form)  
- Exchange server reference: "b1df9935415b@nist.gov" with "/o=ExchangeLabs" - indicating Microsoft Exchange/Office 365

**Outlook execution evidence:**
- UserAssist: OUTLOOK.EXE executed 5 times, last at 2015-03-25 14:41:03
- ShimCache: C:\Program Files\Microsoft Office\Office15\OUTLOOK.EXE (2012-10-02, Executed)
- ShimCache: C:\Program Files\Common Files\Microsoft Shared\Office15\OLicenseHeartbeat.exe (executed - licensing)
- ShimCache: C:\Program Files\Microsoft Office\Office15\MsoSync.exe (executed - document sync)

**Outlook data files on disk (tsk.filelist):**
- Users/informant/AppData/Local/Microsoft/Outlook/RoamCache/ - contains multiple stream data files:
  - Stream_ContactPrefs_2_*.dat
  - Stream_ConversationPrefs_2_*.dat
  - Stream_RssRule_2_*.dat (created 2015-03-22 15:48:40)
- Note: OST files are excluded from volume shadow copies per BackupRestore registry setting

**iCloud Mail also configured:**
- MFT shows iCloud Mail.lnk shortcut created at 2015-03-23 20:01:53 in Start Menu

The email account "iaman.informant@nist.gov" confirms the user's organizational affiliation with NIST, consistent with access to the "secured_drive" network share containing government project documents. The Outlook client was among the most-executed applications (5 times), and was last used on the final day (March 25) before the system was cleaned with CCleaner and Eraser.



### 23. [INFO] Network Configuration: PC at 10.11.11.129 on Same Subnet as File Server 10.11.11.128

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-25T15:19:50 |
| **Sources** | registry.system |
| **Evidence Refs** | tc_84e21422 |


Registry analysis reveals the PC's network configuration and its relationship to the file server containing the stolen data.

**PC Network Configuration (registry.system - nic2 plugin):**
- DHCP-assigned IP: 10.11.11.129
- Subnet mask: 255.255.255.0
- Default Gateway: 10.11.11.2
- DNS Server: 10.11.11.2
- DHCP Server: 10.11.11.254
- Domain: localdomain
- Lease obtained: 2015-03-25 15:19:50
- Lease duration: 1800 seconds (30 minutes)

**Mounted Devices and Drive Mappings:**
- C: - System hard drive (disk signature f0 26 57 20)
- D: - CD/DVD-ROM drive (IDE CdRom, VMware virtual - device: IDE#CdRomNECVMWar_VMware_SATA_CD01)
- E: - USB removable device (disk signature e2 21 03 4c, volume mounted 2015-03-24 13:21:10)
- V: - NOT in MountedDevices (not a physical volume) → confirming V: was a mapped network drive to \\10.11.11.128\secured_drive

The file server at 10.11.11.128 with the "secured_drive" share is on the SAME subnet as the PC (10.11.11.129). The V: drive mapping is confirmed by shellbag entries showing identical MFT file references between "My Computer\V:\Secret Project Data" and "My Network Places\10.11.11.128\\secured_drive\Secret Project Data" (both MFT ref 43045/1).

The E: drive (USB) was first detected on 2015-03-24 13:21:10, which coincides with the shellbag activity showing the informant browsing the USB's Secret Project Data directories starting at 2015-03-24 13:38:31.

Computer names observed in the evidence:
- informant-PC (current hostname from Hayabusa)
- WIN-D9RGPJQ68G8$ (original machine account from initial setup events)
- 37L4247F27-25 (name seen in firewall events during initial setup)



### 24. [INFO] PC User Accounts Analysis: informant (Primary Actor), admin11/ITechTeam/temporary (Administrative Setup Accounts)

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54 to 2015-03-22T15:57:02 |
| **Sources** | registry.sam, ez.mft, tsk.timeline |
| **Evidence Refs** | tc_dc24ee7e, tc_c1d62ec9 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


SAM registry analysis reveals 4 user accounts created on 2015-03-22, all within a 1.5-hour window, suggesting this PC was freshly set up for the user on that date:

**Primary Actor — "informant" [RID 1000]:**
- Account Type: Default Admin User
- Created: 2015-03-22T14:33:54 (first account created)
- Password Hint: "IAMAN" (matches RM2 volume label "IAMAN $_@" and RM3 label "IAMAN CD")
- Last Login: 2015-03-25T14:45:59 (final day of activity)
- Login Count: 10 (consistent with 4 days of use: Mar 22-25)
- SID: S-1-5-21-2425377081-3129163575-2985601102-1000
- Group: Administrators
- All exfiltration activity traces to this account

**Administrative Account — "admin11" [RID 1001]:**
- Account Type: Default Admin User
- Created: 2015-03-22T15:51:54 (1hr 18min after informant)
- Last Login: 2015-03-22T15:57:02
- Login Count: 2
- Group: Administrators + Users
- MFT shows Burn directory created under admin11 profile at 2015-03-22T15:54:04
- Likely an IT administrator account that set up the PC and Google Chrome

**IT Account — "ITechTeam" [RID 1002]:**
- Account Type: Default Admin User
- Created: 2015-03-22T15:52:30 (immediately after admin11)
- Last Login: Never
- Login Count: 0
- Group: Administrators + Users
- Never logged in; likely a shared IT team admin account

**Limited Account — "temporary" [RID 1003]:**
- Account Type: Custom Limited Acct
- Created: 2015-03-22T15:53:01 (seconds after ITechTeam)
- Last Login: 2015-03-22T15:55:57
- Login Count: 1
- Group: Users only
- MFT shows basic profile creation with AutomaticDestinations and Windows libraries
- Likely a test/temporary account for verifying limited user functionality

**Assessment:**
The accounts admin11, ITechTeam, and temporary were all created within 80 seconds of each other, suggesting an IT administrator set up the machine with standard organizational accounts. Only "informant" was the active user responsible for the data exfiltration. The "admin11" account's single login with Burn directory and Google Chrome data is consistent with initial PC setup.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| External IP | `129.6.58.42` | United States, AS49 National Institute of Standards and Technology | Google Drive and iCloud Installed and Executed — Cloud Exfiltration Channels Pre |
| Internal IP | `10.11.11.128` |  | Network Share \\10.11.11.128\secured_drive Identified as Original Source of Secr |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Program` |  | Google Drive and iCloud Installed and Executed — Cloud Exfiltration Channels Pre |
| Path | `C:\Users\informant\Downloads\googledrivesync.exe` |  | Google Drive and iCloud Installed and Executed — Cloud Exfiltration Channels Pre |
| Path | `C:\Users\informant\Downloads\icloudsetup.exe` |  | Google Drive and iCloud Installed and Executed — Cloud Exfiltration Channels Pre |
| Path | `C:\Users\Public\Desktop\CCleaner.lnk` |  | Complete Anti-Forensic Countermeasure Sequence: Research → File Masquerading → D |
| Path | `C:\Users\Public\Desktop\Eraser.lnk` |  | Complete Anti-Forensic Countermeasure Sequence: Research → File Masquerading → D |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `david.beaty@jpl.nasa.gov` |  | Sensitive "Secret Project" Documents Found on USB Device RM1 |
| Email | `karen.l.buxbaum@jpl.nasa.gov` |  | Sensitive "Secret Project" Documents Found on USB Device RM1 |
| Email | `mmeyer@mail.hq.nasa.gov` |  | Sensitive "Secret Project" Documents Found on USB Device RM1 |
| Email | `eric_p._lauer@omb.eop.gov` |  | Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Re |
| Email | `mmun@loc.gov` |  | Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Re |
| Email | `th276a@nih.gov` |  | Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Re |
| Email | `wayne.longman@att.net` |  | Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Re |
| Email | `iaman.informant@nist.gov` |  | Environment-Wide: NASA/JPL Mars Exploration Documents Identified Across All 3 Re |
| Email | `informant@accounts.google.com` |  | Google Account Authentication Confirms Webmail Access: "informant@accounts.googl |
| Email | `iaman@nist.gov` |  | Cross-System Exfiltration Chain: Secret Project Documents Traced PC → RM1 → RM2  |




---

## Appendix C: MITRE ATT&CK Coverage

15 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Execution (1) > Persistence (1) > Privilege Escalation (1) > Defense Evasion (7) > Collection (3) > Command and Control (1) > Exfiltration (3)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Resignation Letter Created on Final Day...; PC User Accounts Analysis: informant (Primary... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Application Execution Summary: Office Suite,... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Resignation Letter Created on Final Day...; PC User Accounts Analysis: informant (Primary... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Resignation Letter Created on Final Day...; PC User Accounts Analysis: informant (Primary... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Complete Anti-Forensic Countermeasure... |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | PC Search History Reveals Extensive Insider... |
| [T1036.007](https://attack.mitre.org/techniques/T1036/007/) | Double File Extension | Massive File Extension Masquerading on RM2 -...; Deleted Cover Images on RM2 Suggest... |
| [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | Masquerade File Type | Cross-System Exfiltration Chain: Secret...; Complete Anti-Forensic Countermeasure... |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | PC Search History Reveals Extensive Insider...; Multi-Session Disc Burning Shows Concealment...; Complete Anti-Forensic Countermeasure... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Deleted Cover Images on RM2 Suggest...; All Files on RM2 Are Deleted — Device Was...; PC Recycle Bin Contains Deleted Windows Sample...; Cross-System Exfiltration Chain: Secret...; Complete Anti-Forensic Countermeasure... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Resignation Letter Created on Final Day...; PC User Accounts Analysis: informant (Primary... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Massive File Extension Masquerading on RM2 -...; PC User "informant" Accessed Secret Project...; Environment-Wide: NASA/JPL Mars Exploration...; Application Execution Summary: Office Suite,...; Local "S data" Staging Directory on Desktop...; Cross-System Exfiltration Chain: Secret...; Network Share \\10.11.11.128\secured_drive... |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network Share \\10.11.11.128\secured_drive... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Local "S data" Staging Directory on Desktop...; Cross-System Exfiltration Chain: Secret...; Network Share \\10.11.11.128\secured_drive... |


### Command and Control

| Technique | Name | Findings |
|-----------|------|----------|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | Google Account Authentication Confirms Webmail... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Sensitive "Secret Project" Documents Found on...; Massive File Extension Masquerading on RM2 -...; PC User "informant" Accessed Secret Project...; PC Search History Reveals Extensive Insider...; Multi-Session Disc Burning Shows Concealment...; PC Registry and Timeline Prove User...; EXIF Hash-Level Confirmation: Embedded...; Cross-System Exfiltration Chain: Secret...; Network Share \\10.11.11.128\secured_drive... |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | PC Search History Reveals Extensive Insider...; Google Drive and iCloud Installed and Executed... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Google Account Authentication Confirms Webmail...; Google Drive and iCloud Installed and Executed... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 630 |
| Findings submitted | 24 |
| Confirmed | 21 |
| Inferences | 3 |
| Input tokens | 55.9K |
| Output tokens | 228.4K |
| Total tokens | 284.2K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 55.9K | 228.4K | 284.2K |




<details>
<summary>Evidence Sources (123)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 8 |
| tsk.fsstat | sleuthkit | 37 |
| tsk.filelist | sleuthkit | 27 |
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| tsk.masquerade | sleuthkit | 17 |
| tsk.partitions | sleuthkit | 10 |
| ez.mft | eztools | 98918 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 5206 |
| bulk.duplicates | bulk_extractor | 1298 |
| bulk.email | bulk_extractor | 15 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 5226 |
| bulk.url_services | bulk_extractor | 25 |
| bulk.zip_carved | bulk_extractor | 3851 |
| hashdeep.hashes | hashdeep | 6 |
| tsk.timeline | sleuthkit | 67 |
| strings.output | strings | 22065 |
| exiftool.metadata | exiftool | 9 |
| tsk.masquerade | sleuthkit | 0 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 7330 |
| bulk.duplicates | bulk_extractor | 1742 |
| bulk.email | bulk_extractor | 61 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7192 |
| bulk.url_services | bulk_extractor | 58 |
| bulk.zip_carved | bulk_extractor | 5221 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| tsk.timeline | sleuthkit | 187 |
| strings.output | strings | 165747 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 403938 |
| bulk.duplicates | bulk_extractor | 6623 |
| bulk.email | bulk_extractor | 6970 |
| bulk.ether | bulk_extractor | 6 |
| bulk.exif | bulk_extractor | 794 |
| bulk.jpeg | bulk_extractor | 9 |
| bulk.rfc822 | bulk_extractor | 7326 |
| bulk.url | bulk_extractor | 458564 |
| bulk.url_facebook-address | bulk_extractor | 19 |
| bulk.url_searches | bulk_extractor | 155 |
| bulk.url_services | bulk_extractor | 3681 |
| bulk.winpe | bulk_extractor | 29729 |
| bulk.winpe_carved | bulk_extractor | 29704 |
| bulk.zip_carved | bulk_extractor | 22411 |
| evtx.manifest | evtx-extract | 54 |
| ez.shimcache | eztools | 307 |
| registry.system | regripper | 391 |
| registry.query.system | python-registry | 1 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.query.software | python-registry | 1 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| tsk.timeline | sleuthkit | 344089 |
| registry.software | regripper | 33492 |
| registry.software | regripper | 283 |
| registry.query.system | python-registry | 1 |
| registry.software | regripper | 283 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.query.system | python-registry | 1 |
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
| tsk.masquerade | sleuthkit | 3 |
| chainsaw.hunt | chainsaw | 99 |
| hayabusa.alerts | hayabusa | 35 |
| regripper.cfreds_2015_data_leakage_pc | regripper | 0 |
| optical.listing | mulder-optical | 58 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| strings.output | strings | 34815 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 7303 |
| bulk.duplicates | bulk_extractor | 1738 |
| bulk.email | bulk_extractor | 30 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7204 |
| bulk.url_services | bulk_extractor | 60 |
| bulk.zip_carved | bulk_extractor | 5221 |
| composite.file_staging | composite | 578 |
| composite.execution | composite | 122 |
| composite.timeline | composite | 172 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.defense_evasion | composite | 211 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.recovery | composite | 22 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2486 |
| composite.exfil | composite | 2486 |
| composite.execution | composite | 122 |
| composite.defense_evasion | composite | 190 |
| composite.file_staging | composite | 578 |
| composite.timeline | composite | 172 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.recovery | composite | 22 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| enrichment.iocs | enrichment | 47 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
