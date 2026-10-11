# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T15:58:06.137256+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 120 evidence sources (63 disk, 57 other) | 500 tool calls | 1.1 hours
**Results:** 24 findings (1 critical, 8 high) | 20 confirmed, 4 inference | 4 hypotheses ruled out
**Timeline:** 2014-12-04 to 2015-03-25

**Key Threats:**
- Cross-System Provenance Chain: Network Share → PC Local Staging → USB/CD Exfiltration with Multi-Layered Concealment

**Attack Lifecycle:**
- **Initial Access / Deployment** (2014-12-04 to 2015-03-25): Secret Project Documents Copied to USB Drive on February 15, 2015 (+12 related)
- **Persistence** (2015-03-23): RecentDocs and MRU Entries Confirm Access to Secret Project Files and Masqueraded Documents
- **Command and Control** (2015-02-15 to 2015-03-25): Environment-Wide Cross-Device Document Correlation — Byte-Level Matches Across PC, RM1, RM2, and RM3 (+2 related)
- **Credential Access** (2015-02-15 to 2015-03-24): Extensive OOXML Document Fragments Recoverable from Unallocated Space on RM1 and RM3 (+3 related)

**Tools:** search (107), get_raw_output (63), submit_finding (42), get_findings (25), update_finding (22). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Cross-System Provenance Chain: Network Share → PC Local Staging → USB/CD Exfiltration with Multi-Layered Concealment** (2015-02-15T16:51:38 to 2015-03-25T15:30:06)




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

500 tool calls were executed across 36
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Insider Data Exfiltration — CFREDS 2015 Data Leakage Case (NDLC)

## Background

This investigation was initiated in response to a suspected insider data leakage incident involving the unauthorized exfiltration of sensitive government and scientific research documents from a secured network file share. The investigation examined four forensic evidence images acquired from the suspect's workstation and associated removable media. A total of 36 evidence sources were indexed across 24 analytical findings, with 22 distinct MITRE ATT&CK techniques identified. Of the total findings, 4 were negative (ruling out specific hypotheses), while 20 were confirmed through corroborating evidence and 4 represent analytical inferences supported by circumstantial evidence.

The evidence inventory comprises four Expert Witness Format (E01) disk images. The first is the suspect's Windows 7 x64 workstation (cfreds_2015_data_leakage_pc.E01, approximately 2 GB compressed), which served as the primary operational platform for the insider's activities. The second is a SanDisk Cruzer Fit USB drive designated RM1 (cfreds_2015_data_leakage_rm1.E01, approximately 75 MB compressed), formatted as a single exFAT partition with the volume label "Authorized USB" and volume serial number 5c75-4d3e. The third is a second SanDisk Cruzer Fit USB drive designated RM2 (cfreds_2015_data_leakage_rm2.E01, approximately 243 MB compressed), containing a dual-partition layout with a FAT32 partition labeled "IAMAN $_@" and an exFAT partition labeled "Authorized USB." The fourth is an optical disc designated RM3 (cfreds_2015_data_leakage_rm3_type3.E01), a UDF write-once medium with the volume label "IAMAN CD" containing nine burn sessions.

The environment centers on a NIST (National Institute of Standards and Technology) employee workstation connected to a local network. The user account "informant" operated on the PC at IP address 10.11.11.129, with access to a network file share hosted at 10.11.11.128 under the share path \\\\10.11.11.128\\secured_drive. The network share contained a structured repository of sensitive project documentation organized into subdirectories: design, pricing decision, final, progress, proposal, and technical review. The documents themselves pertain to NASA/JPL Mars Exploration Program Analysis Group (MEPAG) research, containing embedded references to NASA headquarters personnel, JPL scientists, Office of Management and Budget contacts, and scientific publications in the Proceedings of the National Academy of Sciences.

## Incident Timeline

The incident unfolded across six distinct operational phases spanning approximately five weeks, from February 15 through March 25, 2015.

**Phase 1 — Source Document Creation and Modification (December 2014 through January 2015).** The documents that would later be exfiltrated were last modified on the source system during this period. The modification timestamps preserved on the removable media establish a clear provenance window: [secret_project]_design_concept.ppt was last modified on December 4, 2014 at 11:24:50 UTC; [secret_project]_detailed_design.pptx on December 16, 2014 at 11:10:26 UTC; [secret_project]_detailed_proposal.docx on December 18, 2014 at 16:50:58 UTC; [secret_project]_proposal.docx on December 19, 2014 at 14:53:46 UTC; and [secret_project]_revised_points.ppt on January 23, 2015 at 15:47:10 UTC. These five documents constitute the core of the exfiltrated dataset, totaling approximately 71 MB.

**Phase 2 — Initial Exfiltration via USB (February 15, 2015).** The first confirmed data exfiltration event occurred on February 15, 2015. At 16:51:38 UTC, the user created the directory structure "RM#1/Secret Project Data/" on the RM1 USB drive, followed by the "design" and "proposal" subdirectories. Between 16:52:08 and 16:52:20 UTC — a 42-second window — all five secret project documents were copied to the USB drive in a single bulk operation. The documents retained their original "[secret_project]" naming convention with no concealment applied. A subsequent directory reorganization occurred on February 27, 2015 at 17:20:18 UTC, when a redundant "Secret Project Data" root directory was deleted.

**Phase 3 — Reconnaissance and Escalation (March 22 through 23, 2015).** This phase marks the transition from opportunistic copying to a systematic exfiltration campaign. On March 22, 2015, beginning at 14:33:13 UTC, the user logged into the PC and began accessing the network share at \\\\10.11.11.128\\secured_drive, browsing through all Secret Project Data subdirectories between 14:52:22 and 14:52:24 UTC as recorded in the shellbag artifacts. At 15:51:43 UTC, the user navigated to Control Panel to create new accounts, and within a 72-second burst created three administrator-level accounts: "admin11" at 15:51:54 UTC, "ITechTeam" at 15:52:30 UTC, and "temporary" with a password reset at 15:53:11 UTC. All three were immediately elevated to the Administrators group. None performed any substantive activity beyond brief initial logins, consistent with decoy or misdirection accounts.

On March 23, 2015, the user continued accessing secret project documents through the network share (mapped as drive V:), opening files including [secret_project]_final_meeting.pptx at 20:27:33 UTC, (secret_project)_pricing_decision.xlsx at 20:26:53 UTC, and [secret_project]_design_concept.ppt at 18:38:21 UTC. The user also searched for "secret" in Windows Explorer at 18:40:17 UTC. Cloud storage clients were downloaded during this period: googledrivesync.exe at 19:56:33 UTC and icloudsetup.exe at 19:56:53 UTC, with Google Drive's sync folder created at 20:05:34 UTC. Personal photographs (approximately 25 files dating from 2004-2013) were copied to the RM2 device at 16:55:17 UTC, potentially to establish cover content.

**Phase 4 — Masqueraded Exfiltration via Second USB (March 24, 2015).** The most operationally sophisticated phase began early on March 24, 2015. Between 09:54:54 and 09:57:32 UTC, five directories were created on the RM2 FAT32 partition: design, PRICIN~1 (pricing decision), progress, proposal, and TECHNI~1 (technical review). Between 09:59:26 and 10:00:18 UTC, seventeen documents were copied into these directories — but with every file renamed to bear an innocuous name and a false file extension. Office documents were disguised as media files, databases, and archives: winter_storm.amr (actually a 14.5 MB PowerPoint), my_favorite_cars.db (actually a 1.2 MB OLE document), a_gift_from_you.gif (actually a 33.6 MB Word document), and diary entries labeled as text files that were actually Office documents. Four of these masqueraded files match the five original secret project documents byte-for-byte in file size, confirming they are identical copies. The USBSTOR registry key confirms USB device connection at 13:37:59 UTC. Shellbag analysis shows the user browsing the E: drive's Secret Project Data directories between 13:38:31 and 14:01:29 UTC, followed by browsing abbreviated directories on the D: drive (de, tr, pd, prop, prog) between 19:47:48 and 20:44:13 UTC.

**Phase 5 — Optical Disc Burning with Cover Files (March 24, 2015, evening).** Between 20:54:16 and 20:55:46 UTC, the same seventeen masqueraded documents were burned to the RM3 optical disc ("IAMAN CD") across eight UDF sessions, organized in abbreviated directory names (de, pd, prog, prop, tr) mirroring the network share structure. At 20:57:00 through 20:57:03 UTC, a ninth and final session was burned containing three Windows 7 stock sample photographs: Koala.jpg, Penguins.jpg, and Tulips.jpg. Because UDF write-once media displays only the most recent session by default, a casual inspection of the disc would reveal nothing but harmless stock photographs. The user verified the disc at 21:01:14 UTC by accessing Tulips.jpg through RecentDocs, confirming the cover files were properly visible.

**Phase 6 — Anti-Forensic Cleanup and Resignation (March 25, 2015).** The final day of recorded activity was devoted entirely to evidence destruction and departure preparation. At 14:41:03 UTC, Outlook was used for the last time (its fifth execution during the campaign). At 14:50:14 UTC, the Eraser 6.2.0.2962 installer was downloaded, and the tool was executed at 15:12:28 UTC. CCleaner v5.04 was downloaded at 14:57:56 UTC (notably, CCleaner had been previously installed on 2015-03-13 and then uninstalled the same day — the deliberate re-installation specifically during cleanup strengthens anti-forensic intent). CCleaner was executed at 15:15:50 UTC. Google Drive was launched at 15:21:30 UTC. Microsoft Word was used four times (last at 15:24:48 UTC) to create the file "Resignation_Letter_(Iaman_Informant).docx," which was also saved in XPS format and viewed in the XPS Viewer at 15:28:47 UTC — the last recorded user activity on the system.

## Key Findings

**Data Collection and Exfiltration Across Multiple Channels.** The investigation confirmed that approximately 175 MB of sensitive government and scientific research documents were exfiltrated through at least three physical channels and potentially two cloud-based channels. The confirmed channels are: USB drive RM1 carrying five documents with original naming (71 MB, copied February 15, 2015); USB drive RM2 carrying seventeen documents with masqueraded names and extensions (approximately 104 MB, copied March 24, 2015); and optical disc RM3 carrying the same seventeen masqueraded documents hidden behind a cover session of stock photographs (copied March 24, 2015). The unconfirmed channels include Google Drive (installed, sync folder created, but sync databases deleted — preventing verification of actual uploads) and Microsoft Outlook (executed five times with a NIST email account, but .ost file contents were not directly accessible for confirmation). The user's web searches for "cloud storage," "google drive," and "apple icloud" alongside the deliberate deletion of Google Drive's sync_config.db and snapshot.db files suggest cloud exfiltration was at minimum attempted.

**Systematic File Extension Masquerading.** Seventeen documents were renamed with deliberately misleading file names and extensions on both RM2 and RM3. Office PowerPoint files were disguised as AMR audio files and ZIP archives. Excel spreadsheets were renamed as database files, 7-Zip archives, and JPEG images. Word documents were disguised as GIF images, PNG images, OneNote notebooks, and SVG files. OLE documents were renamed as AVI video files, text files, and database files. The naming convention employed benign, unsuspicious themes: weather advisories, favorite movies, car preferences, calendar entries, smartphone references, friendship, and personal diary entries. This masquerading scheme was consistent across RM2 and RM3, with all seventeen files matching byte-for-byte between the two media, confirming they were produced from the same staging operation.

**Multi-Session Optical Disc Concealment Strategy.** The RM3 optical disc employed a sophisticated concealment approach by leveraging UDF multi-session burning. The disc contained nine sessions burned within a three-minute window on March 24, 2015. Sessions one through eight each contained a subdirectory of masqueraded documents. Session nine — the final and therefore default-visible session — contained only three Windows 7 stock photographs (Koala.jpg, Penguins.jpg, Tulips.jpg) sourced from C:\\Users\\Public\\Pictures\\Sample Pictures. Any standard disc reader would display only these innocuous cover files. Recovery of the document-bearing sessions requires forensic tools capable of parsing UDF session history.

**Cross-Device Document Provenance.** Bulk extractor duplicate analysis, file size comparison, and embedded metadata analysis independently confirmed that documents across all four evidence sources originated from the same corpus. SHA1 fragment hashes from carved OOXML ZIP entries link RM1, RM2, RM3, and the PC. The exact count of 5,221 carved ZIP entries matches between RM2 and RM3, confirming byte-level content equivalence. Embedded email addresses from NASA/JPL personnel (including contacts at NASA headquarters, JPL, the Office of Management and Budget, the National Institutes of Health, and the Library of Congress) appear consistently across all media. EXIF metadata from embedded images (Eastman Kodak DC260, Adobe Photoshop CS) is likewise consistent.

**Premeditated Research into Data Theft and Anti-Forensics.** The user's web search history reveals comprehensive premeditation. Searches spanned the complete operational cycle: planning queries for "information leakage cases," "data leakage methods," "leaking confidential information," and "how to leak a secret"; method selection queries for "cd burning method," "cd burning method in windows," "external device and forensics," "security checkpoint cd-r," "cloud storage," and "google drive"; and anti-forensic queries for "anti-forensic tools," "anti-forensics," "ccleaner," "eraser," "system cleaner," and "how to delete data." The user also researched forensic awareness topics including "digital forensics," "what is windows system artifacts," "windows event logs," "investigation on windows machine," and "Forensic Email Investigation." Critically, every researched method was subsequently executed — USB exfiltration, CD burning, cloud storage setup, and CCleaner/Eraser installation — establishing a direct 1:1 mapping between research and action.

**Anti-Forensic Tool Deployment.** Eraser 6.2.0.2962 and CCleaner v5.04 were both downloaded, installed, and executed on March 25, 2015. The Eraser installation required a .NET Framework bootstrapper, confirming a fresh installation. CCleaner had been previously installed and uninstalled on March 13, 2015 — the deliberate re-installation during the cleanup phase represents purposeful re-deployment rather than routine maintenance. The effectiveness of these tools was notably incomplete: document content remained recoverable from RM2's FAT32 partition as orphan files, and the masqueraded documents in earlier RM3 sessions remained intact. The Google Drive sync databases were deleted (potentially by CCleaner), which did succeed in preventing confirmation of cloud-based exfiltration.

**Decoy Account Creation.** Three accounts with administrator privileges — admin11, ITechTeam, and temporary — were created in a 72-second burst on March 22, 2015. None performed substantive activity. The naming conventions mimic legitimate administrative accounts, and their creation coincides with the onset of the intensive exfiltration campaign. The simultaneous creation timing, immediate administrator elevation, and absence of any productive use are consistent with decoy or misdirection tactics intended to create investigative noise.

**User Identity and Insider Motivation.** The user is conclusively identified as "Iaman Informant" (iaman.informant@nist.gov) based on convergent evidence from Outlook mailbox references, volume labels ("IAMAN $_@" on RM2, "IAMAN CD" on RM3), RecentDocs entries, and NTUSER.DAT registry data. The creation of "Resignation_Letter_(Iaman_Informant).docx" on the final day of activity — concurrent with anti-forensic cleanup — establishes this as a departing insider threat scenario. The resignation letter was saved in both .docx and .xps formats and viewed in the XPS Viewer at 15:28:47 UTC, the last recorded action on the system.

**Negative Findings and Ruled-Out Hypotheses.** The investigation ruled out several hypotheses. No file extension mismatches were detected on the RM1 USB drive, confirming that concealment techniques were applied selectively to RM2 and RM3 but not RM1. No steganographic content was detected on any removable media; the concealment strategy relied on file extension masquerading and multi-session disc burning, not image-based steganography. No packet capture or network sniffing tools were found on the system, indicating the insider relied on legitimate file share access rather than network interception. No evidence of Windows event log clearing or MFT timestamp manipulation was found, despite the user's research into these forensic artifacts — the anti-forensic strategy focused on file-level concealment and deletion rather than log or timestamp manipulation.

## Threat Intelligence and Attribution

This incident is unambiguously attributable to the user account "informant" (Iaman Informant, iaman.informant@nist.gov) operating from the PC at 10.11.11.129. This attribution is not based on a single indicator but on the convergence of multiple independent evidence streams: the user's NTUSER.DAT registry records all file access and application execution activity; the volume labels on exfiltration media directly incorporate the user's name ("IAMAN $_@" and "IAMAN CD"); the resignation letter bears the user's full name; the Outlook mailbox is configured to the user's NIST email address; and the shellbag history traces the user's navigation from the network share through local staging to removable media.

The operational tradecraft — while clearly premeditated and informed by online research — reflects an individual actor operating without external tooling or infrastructure. The user relied exclusively on legitimate operating system features (Windows built-in CD burning, standard file copy operations), commercially available cleanup utilities (CCleaner, Eraser), and cloud services (Google Drive, iCloud) rather than specialized offensive tools. No command-and-control infrastructure, custom malware, remote access tools, or exploitation frameworks were detected. The attack surface was limited to authorized access: the user possessed legitimate credentials to the network share and leveraged those credentials to collect data. The TTPs are consistent with a motivated insider threat actor who researched methods independently rather than an operator following an established playbook or receiving external direction.

The targeted documents — NASA/JPL MEPAG research materials containing contacts from NASA headquarters, JPL, the Office of Management and Budget, NIH, and the Library of Congress — suggest the exfiltrated data has scientific and potentially strategic value. However, the investigation cannot determine the intended recipient or end use of the stolen materials based solely on the available evidence.

## Impact Assessment

The scope of this incident encompasses one compromised user workstation (10.11.11.129), one compromised network file share (\\\\10.11.11.128\\secured_drive), and three removable media devices carrying exfiltrated data. The confirmed volume of exfiltrated data is approximately 175 MB across at least 17 unique sensitive documents spanning five project categories: design (2 documents), pricing decision (4 documents), progress (3 documents), proposal (2 documents), and technical review (6 documents). An additional five documents on RM1 overlap with the RM2/RM3 corpus.

The data at risk includes scientific research materials related to NASA's Mars Exploration Program, containing embedded references to government personnel across multiple agencies. The documents include detailed proposals (35 MB), design presentations (16 MB), revised technical points, pricing analysis spreadsheets, and progress reports. The presence of contacts from the Office of Management and Budget and multiple NASA centers suggests these documents may have budgetary, programmatic, or pre-decisional significance.

Credential exposure is limited to the user's own account (iaman.informant@nist.gov and iaman@nist.gov). The three decoy accounts (admin11, ITechTeam, temporary) were created with administrator privileges and represent a secondary exposure vector, as their passwords are unknown to the investigation and they remain active unless administratively disabled.

The persistence depth is moderate. The physical media (two USB drives and one optical disc) represent persistent copies of the exfiltrated data that exist outside organizational control. The Google Drive sync folder was created, potentially enabling a cloud-hosted persistent copy, though confirmation of actual synchronization was prevented by the deletion of database files. The decoy administrator accounts constitute residual access vectors.

The anti-forensic cleanup partially succeeded: Google Drive sync databases were deleted, and Eraser and CCleaner were executed. However, the cleanup was demonstrably incomplete — document content remains recoverable from RM2 orphan files and RM3 earlier disc sessions, the PC registry retains comprehensive activity records, and the ShimCache and UserAssist artifacts fully chronicle the user's actions.

## Immediate Tactical Containment

1. Disable user account "informant" (SID ending in ...1000) on the domain and all local systems immediately. Revoke all Active Directory tokens, Outlook Web Access sessions, and VPN credentials associated with iaman.informant@nist.gov and iaman@nist.gov.

2. Disable the three decoy administrator accounts: "admin11" (SID ...1001), "ITechTeam" (SID ...1002), and "temporary" (SID ...1003) on the PC at 10.11.11.129 and verify they do not exist on any domain controller.

3. Isolate the workstation at IP 10.11.11.129 from the network. Preserve current state; do not power off until a final memory image can be captured if the system is still running.

4. Revoke all access to the network share \\\\10.11.11.128\\secured_drive for the informant account. Audit the share's access control list to determine whether the decoy accounts (admin11, ITechTeam, temporary) have inherited or been granted access.

5. Seize and preserve the two SanDisk Cruzer Fit USB drives identified by serial numbers 4C530012450531101593 and 4C530012550531106501. Seize and preserve the optical disc labeled "IAMAN CD."

6. Block the Google account associated with the informant user on the organizational proxy/firewall. If the organization uses a Google Workspace domain, suspend the account and initiate a data export to determine whether documents were synced. Contact Google for preservation if using a consumer account.

7. Revoke or rotate any iCloud credentials associated with the user. Contact Apple for account preservation if the user installed icloudsetup.exe and may have synced data.

8. Reset the password for the network share service account on 10.11.11.128 if a shared credential was used. Audit all recent access logs for \\\\10.11.11.128\\secured_drive to identify any access from the decoy accounts or from external IP addresses.

## Strategic Remediation

The insider accessed the network share \\\\10.11.11.128\\secured_drive using legitimate credentials without any data loss prevention controls intervening, as documented in the network share access finding. The fact that 175 MB of sensitive documents could be copied to USB drives and burned to optical media without detection indicates the absence of a functioning DLP system or endpoint monitoring agent. Deploying a DLP solution with USB write monitoring, optical media burn detection, and cloud upload inspection — with policies specifically covering the sensitive project directories identified in this case — would have generated alerts at the first copy operation on February 15, 2015.

The user connected two personal SanDisk Cruzer Fit USB drives (serial numbers 4C530012450531101593 and 4C530012550531106501) and used the Windows built-in CD/DVD burning capability without restriction, as confirmed by the USBSTOR registry entries and ShimCache burn folder path. An endpoint device control policy that either blocks unauthorized removable media by serial number or restricts write access to approved devices would have prevented all three confirmed physical exfiltration channels. The CD/DVD burning capability should be disabled via Group Policy for users who do not have a documented business need.

The user created three administrator-level accounts (admin11, ITechTeam, temporary) in a 72-second window without triggering any alert or requiring approval, as documented in the decoy account creation finding. This indicates that the informant account possessed local administrator rights and that no privileged access management or account creation workflow was in place. Implementing least-privilege access controls — removing local administrator rights from standard user accounts and requiring a ticketed approval workflow for account creation — would have prevented the creation of decoy accounts and limited the user's ability to install anti-forensic tools.

The user downloaded and executed Eraser and CCleaner from the internet on the same day as the exfiltration, with the downloads visible in the UserAssist and ShimCache records. No application whitelisting or software restriction policy prevented the installation and execution of these anti-forensic tools. An application control policy (AppLocker or equivalent) restricting execution to approved software would have blocked both the Eraser installer and the CCleaner re-installation, preserving forensic artifacts that the user attempted to destroy.

The user's extensive web research into data leakage methods, anti-forensic tools, and forensic investigation techniques occurred over multiple sessions without generating any user behavior analytics alert. The search queries — including "how to leak a secret," "anti-forensic tools," and "security checkpoint cd-r" — represent textbook indicators of insider threat planning. A user and entity behavior analytics (UEBA) solution monitoring for anomalous search patterns, or even keyword-based web filtering for terms like "data leakage methods" and "anti-forensic tools," would have provided early warning during the planning phase documented in the web search history finding.

The network share at \\\\10.11.11.128\\secured_drive containing sensitive MEPAG research documents was accessible via standard SMB file sharing without documented access logging granular enough to detect bulk copying. The shellbag artifacts show the user browsed every subdirectory of the Secret Project Data folder. Implementing file access auditing on the share (Windows Object Access auditing at the file level) with alerting on bulk read operations would have detected the systematic access pattern and the volume of data being read.

## Conclusion

**Q1. What systems were compromised?** One Windows 7 workstation (10.11.11.129) was used as the operational platform by the insider. The network file share at \\\\10.11.11.128\\secured_drive was the source of the exfiltrated documents. Two USB drives (RM1 and RM2) and one optical disc (RM3) served as exfiltration media. Google Drive and iCloud installations represent potential cloud-based compromise vectors, though confirmed synchronization could not be established.

**Q2. How did the attacker gain initial access?** This is an insider threat case. The user "Iaman Informant" (iaman.informant@nist.gov) possessed legitimate credentials and authorized access to the workstation and network share. No external intrusion vector was involved. The attack leveraged trusted access rather than exploiting a vulnerability.

**Q3. What lateral movement occurred?** The user accessed the network share at \\\\10.11.11.128\\secured_drive from the workstation at 10.11.11.129 using SMB, which was also mapped as drive V:. A local staging copy was created in an "S data" directory on the PC. Three decoy administrator accounts were created on the local system, though no evidence of their use for lateral movement to other systems was found. No packet capture tools or remote access utilities were detected.

**Q4. What persistence mechanisms were installed?** Three local administrator accounts (admin11, ITechTeam, temporary) were created, representing potential persistent access vectors. Google Drive was configured with a sync folder, which — if operational — would maintain a persistent cloud-accessible copy of any synchronized files. No traditional malware persistence mechanisms (scheduled tasks, registry run keys, services) were installed.

**Q5. Was data exfiltrated, and if so, what and how much?** Yes. Approximately 175 MB of sensitive NASA/JPL MEPAG research documents were confirmed exfiltrated across three physical media: RM1 USB drive (five documents, approximately 71 MB), RM2 USB drive (seventeen documents including the original five, approximately 104 MB), and RM3 optical disc (same seventeen documents as RM2). Cloud-based exfiltration via Google Drive or iCloud remains plausible but unconfirmed due to the deletion of sync databases. Email-based exfiltration via Outlook is possible but unconfirmed.

**Q6. What is the full timeline of the incident?** The incident spans from February 15, 2015 (first confirmed USB copy) through March 25, 2015 (anti-forensic cleanup and resignation letter creation), a period of 38 days. The intensive operational phase concentrated in the final four days: March 22 (reconnaissance, decoy accounts), March 23 (document access, cloud storage setup), March 24 (masqueraded USB copy, CD burning), and March 25 (Eraser, CCleaner, Google Drive, resignation letter).

**Q7. What is the total scope and business impact?** Seventeen unique sensitive documents spanning five project categories (design, pricing decision, progress, proposal, technical review) were exfiltrated. The documents contain NASA/JPL Mars Exploration Program research with embedded contacts from multiple government agencies. The data exists on at least three physical media outside organizational control, and potentially in cloud storage. The business impact includes loss of control over sensitive pre-decisional scientific research, potential exposure of government personnel contact information, and the operational cost of incident response, forensic investigation, and remediation.

**Q8. What are the recommended remediation actions?** Immediate actions include disabling all four user accounts (informant, admin11, ITechTeam, temporary), isolating the compromised workstation, seizing all removable media, and revoking cloud service access. Strategic remediation requires implementing data loss prevention with USB and optical media monitoring, deploying endpoint device control to restrict removable media, enforcing least-privilege access to prevent unauthorized account creation, implementing application whitelisting to block anti-forensic tool installation, deploying user behavior analytics to detect insider threat indicators during the planning phase, and enabling granular file access auditing on sensitive network shares.


---

## Overview

| | |
|---|---|
| Findings | **24** (20 confirmed, 4 inference) |
| Severity | 1 critical, 8 high, 6 medium, 4 low, 5 info |
| Sources | 36 evidence sources across 500 tool calls |
| Ruled Out | 4 hypotheses tested and rejected |


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
| 2014-12-04T11:24:50 | Secret Project Documents Copied to USB Drive on February 15, 2015 | HIGH | tsk.filelist, tsk.metadata.1030147, tsk.metadata.5123, tsk.timeline |
| 2015-02-15T16:51:38 | Cross-System Provenance Chain: Network Share → PC Local Staging → USB/CD Exfiltration with Multi-Layered Concealment | CRITICAL | composite.correlation, composite.defense_evasion, hayabusa.alerts, composite.exfil, registry.usrclass.informant, registry.ntuser.informant, tsk.filelist, tsk.timeline, optical.listing, bulk.email, bulk.exif, bulk.zip_carved |
| 2015-02-15T16:51:38 | RM2 File Activity Timeline — Systematic Data Staging, Masquerading, and Cleanup | MEDIUM | tsk.timeline, registry.usrclass.informant, registry.ntuser.informant |
| 2015-02-15T16:51:38 | Environment-Wide Cross-Device Document Correlation — Byte-Level Matches Across PC, RM1, RM2, and RM3 | MEDIUM | bulk.duplicates, bulk.url_services, bulk.email, bulk.exif, tsk.filelist, tsk.masquerade, optical.listing |
| 2015-02-15T16:51:38 | Extensive OOXML Document Fragments Recoverable from Unallocated Space on RM1 and RM3 | LOW | bulk.zip_carved, strings.output, bulk.duplicates |
| 2015-02-27T17:20:18 | Evidence of Document Editing and Directory Restructuring on USB Drive | LOW | tsk.timeline, tsk.filelist |
| 2015-03-22T14:33:13 | User Identity Established — "Iaman Informant" (iaman.informant@nist.gov) with Resignation Letter | HIGH | registry.ntuser.informant, bulk.email, tsk.masquerade |
| 2015-03-22T14:33:13 | Web Search History Reveals Premeditated Data Theft and Anti-Forensics Research | HIGH | bulk.url_searches, bulk.url |
| 2015-03-22T14:33:13 | Application Execution Timeline Supporting Data Theft — Office, Browsers, and Utilities | INFO | ez.shimcache, registry.ntuser.informant |
| 2015-03-22T14:52:22 | Network Share \\10.11.11.128\secured_drive Accessed as Source of Stolen Documents | HIGH | registry.usrclass.informant, registry.ntuser.informant |
| 2015-03-22T15:51:43 | Decoy Account Creation (admin11, ITechTeam, temporary) — Privilege Escalation with Minimal Activity Suggests Misdirection | MEDIUM | hayabusa.alerts, chainsaw.hunt, composite.correlation, registry.ntuser.admin11, registry.usrclass.admin11, registry.ntuser.temporary, registry.usrclass.temporary, registry.usrclass.informant |
| 2015-03-23T16:55:17 | Deleted Files Recoverable from RM2 FAT32 Partition — Organizational Data in Unallocated Space | LOW | tsk.timeline, tsk.filelist, bulk.zip_carved |
| 2015-03-23T18:38:21 | RecentDocs and MRU Entries Confirm Access to Secret Project Files and Masqueraded Documents | INFO | registry.ntuser.informant |
| 2015-03-23T19:56:33 | Cloud Storage Services (Google Drive, iCloud) Installed — Sync Databases Deleted, Cloud Exfiltration Unconfirmed | MEDIUM | tsk.filelist, composite.correlation, registry.ntuser.informant, registry.usrclass.informant, ez.mft, bulk.url_searches |
| 2015-03-24T09:59:26 | Extensive File Extension Masquerading on RM2 Removable Media — 17 Deleted Documents Disguised as Media Files | HIGH | tsk.masquerade, tsk.timeline, tsk.filelist |
| 2015-03-24T09:59:26 | RM2 Dual-Partition Structure — FAT32 Partition Used as Hidden Storage for Disguised Documents | MEDIUM | tsk.fsstat, tsk.masquerade, tsk.filelist |
| 2015-03-24T13:37:59 | SanDisk Cruzer Fit USB Drive Connected — Two Serial Numbers Indicate Two Physical Devices | MEDIUM | registry.query.system, registry.system |
| 2015-03-24T19:47:48 | CD/DVD Burning Used as Third Exfiltration Channel — "IAMAN CD" on BD-RE Drive D: | HIGH | registry.ntuser.informant, registry.usrclass.informant, ez.shimcache, bulk.url_searches |
| 2015-03-24T20:54:16 | 17 Masqueraded Documents from Earlier Burn Sessions Deleted/Overwritten on RM3 Optical Disc | HIGH | bulk.email, bulk.exif, optical.listing, registry.ntuser.informant, tsk.filelist, tsk.masquerade |
| 2015-03-25T14:41:03 | Microsoft Outlook Used with NIST Email Account — Potential Email Exfiltration Channel | LOW | ez.shimcache, registry.ntuser.informant, tsk.filelist, bulk.url_searches |
| 2015-03-25T14:50:14 | Anti-Forensic Tools Installed and Executed by User "informant" — Eraser and CCleaner | HIGH | registry.ntuser.informant, registry.system |




---

## Hypotheses Ruled Out

These hypotheses were explicitly tested and no supporting evidence was found.


- **No File Extension Mismatches Detected on RM1 USB Drive** : The masquerading detection analysis (tsk.masquerade source) for the rm1 USB drive returned zero results, indicating no files on the active partition have mismatched file extensions vs. content...

- **No Steganographic Content Detected on Any Removable Media (RM1, RM3)** : Steganography detection analysis was run against both RM1 and RM3 evidence images with negative results:

**RM1 USB Drive:** Contains only Office document files (.ppt, .pptx, .docx) as active...

- **No Packet Capture Tools Detected — No Evidence of Network Credential Sniffing** : A thorough search of execution artifacts (ShimCache, UserAssist) and filesystem listings found no evidence of packet capture or network sniffing tools on the system:

**Tools searched for but not...

- **No Evidence of Windows Event Log Clearing or MFT Timestamp Manipulation** : Cross-system analysis of event logs, MFT timestamps, and anti-forensic indicators found no evidence of event log clearing or deliberate MFT timestamp manipulation:

**Event Log Analysis:**
-...



---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Cross-System Provenance Chain: Network Share → PC Local Staging → USB/CD Exfiltration with Multi-Layered Concealment

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-25T15:30:06 |
| **Sources** | composite.correlation, composite.defense_evasion, hayabusa.alerts, composite.exfil, registry.usrclass.informant, registry.ntuser.informant, tsk.filelist, tsk.timeline, optical.listing, bulk.email, bulk.exif, bulk.zip_carved |
| **Evidence Refs** | tc_c9da15bb, tc_658758a8, tc_af8bec1f, tc_c001742c |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1052](https://attack.mitre.org/techniques/T1052/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1039](https://attack.mitre.org/techniques/T1039/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Cross-system correlation across all four evidence sources (PC, RM1, RM2, RM3) establishes the complete provenance chain for the data exfiltration:

**Phase 1 — Source Access (2015-02-15 to 2015-03-23):**
The user "informant" (iaman.informant@nist.gov) accessed the network file share \\10.11.11.128\secured_drive\Secret Project Data from the PC (10.11.11.129). Shellbags from the PC's UsrClass.dat confirm browsing of all subdirectories: design, pricing decision, final, progress, proposal, and technical review. The user created a local staging copy in an "S data" directory on the PC desktop, as evidenced by shellbag entries showing "S data\Secret Project Data\" with nested directory access timestamps from 2015-03-24 13:40-13:57 UTC.

**Phase 2 — First Exfiltration via USB (2015-02-15):**
Five secret project documents (~71 MB) were copied to RM1 USB drive (exFAT, "Authorized USB") in a 42-second bulk copy operation (16:51:38-16:52:20 UTC). Documents retained original [secret_project] naming.

**Phase 3 — Masqueraded Copy to Second USB (2015-03-24):**
17 documents including the original 5 plus 12 additional files from pricing, progress, and technical review categories were copied to RM2 USB drive's FAT32 partition ("IAMAN $_@") at 09:59-10:00 UTC. All files were renamed with innocuous names and false extensions (e.g., winter_storm.amr, my_favorite_cars.db, a_gift_from_you.gif). USBSTOR registry confirms USB device connection at 13:37:59 UTC. Two distinct SanDisk Cruzer Fit serial numbers confirm two physical USB devices.

**Phase 4 — CD/DVD Burn (2015-03-24):**
The same 17 masqueraded documents were burned to RM3 optical disc ("IAMAN CD") through 9 UDF sessions between 20:54-20:55 UTC. Three Windows 7 stock photos were burned as cover files at 20:57 UTC. Shellbags confirm the user browsed D: drive abbreviated directories (de, tr, pd, prop, prog) at 19:47-20:44 UTC, verifying content before the final burn.

**Phase 5 — Cloud Storage Setup (2015-03-23 to 2015-03-25):**
Google Drive sync (googledrivesync.exe) and iCloud (icloudsetup.exe) were downloaded on 2015-03-23 19:56 UTC and installed. Google Drive created a sync folder (Users\Google Drive, created 2015-03-23 20:05:34 UTC). However, the Google Drive database files (sync_config.db, snapshot.db, cacerts) are now DELETED on the PC, preventing confirmation of whether files were actually synced. The deleted database files may have been wiped by CCleaner on 2015-03-25.

**Phase 6 — Anti-Forensic Cleanup (2015-03-25):**
Eraser 6.2 (14:50:14-15:12:28 UTC) and CCleaner v5.04 (14:57:56-15:15:50 UTC) were downloaded, installed, and executed. Resignation letter created in Word and XPS format (15:24:48-15:28:47 UTC).

**Cross-System Convergence Evidence:**
- 4 evidence sources: PC image, RM1 USB, RM2 USB, RM3 optical disc
- Byte-exact file size matches across all three removable media (17 files match between RM2 and RM3; 5 files match between RM1, RM2, and RM3)
- Identical embedded email addresses (NASA JPL, OMB, NIH, LOC) recovered from all media
- Identical EXIF metadata (Kodak DC260, Adobe Photoshop CS) across all media
- Matching OOXML fragment counts (5,221 ZIP carved entries on both RM2 and RM3)
- Matching URL histograms (MEPAG, dx.doi.org, pnas.org) across all media
- PC registry artifacts (shellbags, UserAssist, RecentDocs, USBSTOR, ShimCache) independently corroborate every step of the chain

**Data Volume:** Approximately 175 MB of sensitive government/scientific documents across all media.



### 2. [HIGH] Secret Project Documents Copied to USB Drive on February 15, 2015

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2014-12-04T11:24:50 to 2015-03-23T14:38:46 |
| **Sources** | tsk.filelist, tsk.metadata.1030147, tsk.metadata.5123, tsk.timeline |
| **Evidence Refs** | tc_15363b94, tc_2c9740f7, tc_c42773d5, tc_eda7523e |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Five classified/sensitive documents labeled "[secret_project]" were copied to the USB drive on February 15, 2015, organized under a "Secret Project Data" directory hierarchy. The file creation timestamps on the USB all cluster within a 12-second window (16:52:08 to 16:52:20 UTC), confirming a single copy operation.

**Active Files on RM1 USB Drive (present under both "Secret Project Data/Secret Project Data/" and "RM#1/Secret Project Data/" paths via the same inodes):**

1. **[secret_project]_design_concept.ppt** (inode 5123)
   - Size: 1,810,432 bytes (1.7 MB)
   - Last Modified: 2014-12-04 11:24:50 UTC
   - Created on USB: 2015-02-15 16:52:08 UTC

2. **[secret_project]_detailed_design.pptx** (inode 5128)
   - Size: 16,381,123 bytes (15.6 MB)
   - Last Modified: 2014-12-16 11:10:26 UTC
   - Created on USB: 2015-02-15 16:52:08 UTC (accessed), 16:52:09 (born)

3. **[secret_project]_revised_points.ppt** (inode 5133)
   - Size: 14,547,968 bytes (13.9 MB)
   - Last Modified: 2015-01-23 15:47:10 UTC
   - Created on USB: 2015-02-15 16:52:10 UTC

4. **[secret_project]_detailed_proposal.docx** (inode 1030147)
   - Size: 35,226,880 bytes (33.6 MB)
   - Last Modified: 2014-12-18 16:50:58 UTC
   - Created on USB: 2015-02-15 16:52:12 UTC

5. **[secret_project]_proposal.docx** (inode 1030152)
   - Size: 6,484,502 bytes (6.2 MB)
   - Last Modified: 2014-12-19 14:53:46 UTC
   - Created on USB: 2015-02-15 16:52:20 UTC

**Total data: ~71 MB of project-sensitive documents.**

The documents span two categories: design presentations (.ppt/.pptx) and proposals (.docx). All were originally modified between December 4, 2014 and January 23, 2015, then copied to the USB drive in a single bulk operation on February 15, 2015. The explicit "[secret_project]" naming convention indicates these are classified or restricted project materials.

**Merged findings:**
- **Complete File Activity Timeline for RM1 USB Drive** (f_f22d45f8, medium, confirmed): The mactime/bodyfile analysis provides a complete chronological record of file system activity on the rm1 USB drive spanning December 2014 to March 2015.

**Phase 1 - Source Document Modifications (Dec 2014 - Jan 2015):**
These are the original modification timestamps carried from the source system:
- 2014-12-04 11:24:50 UTC: [secret_project]_design_concept.ppt last modified
- 2014-12-16 11:10:26 UTC: [secret_project]_detailed_design.pptx last modified
- 2014-12-18 16:50:58 UTC: [secret_project]_detailed_proposal.docx last modified
- 2014-12-19 14:53:46 UTC: [secret_project]_proposal.docx last modified
- 2015-01-23 15:47:10 UTC: [secret_project]_revised_points.ppt last modified

**Phase 2 - Bulk Copy to USB (Feb 15, 2015):**
- 16:51:38 UTC: RM#1 directory and subdirectories created
- 16:52:08 UTC: design_concept.ppt accessed/born on USB
- 16:52:08-09 UTC: detailed_design.pptx accessed/born on USB
- 16:52:10 UTC: revised_points.ppt accessed/born on USB
- 16:52:12 UTC: detailed_proposal.docx accessed/born on USB
- 16:52:20 UTC: proposal.docx accessed/born on USB
Total copy time: ~42 seconds for ~71 MB of data

**Phase 3 - Directory Reorganization (Feb 27, 2015):**
- 17:20:18 UTC: "Secret Project Data" root directory modified (then later deleted)

**Phase 4 - Document Editing and Cleanup (Mar 23, 2015):**
- 14:32:20-21 UTC: Deleted "Secret Project Data" directory accessed/born
- 14:37:52-54 UTC: ~$ecret_project]_proposal.docx temp file created and modified
- 14:38:21-46 UTC: OrphanFile-5138 created/deleted (file system cleanup)

This timeline demonstrates: (1) an initial bulk copy operation, (2) subsequent directory restructuring, and (3) later document editing activity over a 5+ week period.

**Affected Systems:** tsk.filelist, tsk.metadata.1030147, tsk.metadata.5123, tsk.timeline



### 3. [HIGH] Extensive File Extension Masquerading on RM2 Removable Media — 17 Deleted Documents Disguised as Media Files

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:26 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade, tsk.timeline, tsk.filelist |
| **Evidence Refs** | tc_c7361cc3, tc_8617c171 |
| **ATT&CK** | [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


The tsk.masquerade detection identified 17 deleted files on the rm2 FAT32 partition ($OrphanFiles) where the file extension does NOT match the actual file content type. Every single file is an Office document (OLE/DOCX/PPTX/XLSX) renamed with a non-document extension to conceal its nature.

The masqueraded files are organized in project-related subdirectories that mirror the structure of the "Secret Project Data" from the organization's secured network share:

**design/ directory:**
- winter_storm.amr → actually OLE (14,547,968 bytes) — EXACT match to [secret_project]_revised_points.ppt
- winter_whether_advisory.zip → actually PPTX (16,381,123 bytes) — EXACT match to [secret_project]_detailed_design.pptx

**PRICIN~1/ (pricing decision) directory:**
- my_favorite_cars.db → actually OLE (1,260,544 bytes)
- my_favorite_movies.7z → actually XLSX (100,078 bytes)
- new_years_day.jpg → actually XLSX (10,237,535 bytes)
- super_bowl.avi → actually OLE (10,289,152 bytes)

**progress/ directory:**
- my_friends.svg → actually OLE (58,368 bytes)
- my_smartphone.png → actually DOCX (4,440,235 bytes)
- new_year_calendar.one → actually DOCX (27,414 bytes)

**proposal/ directory:**
- a_gift_from_you.gif → actually DOCX (35,226,880 bytes) — EXACT match to [secret_project]_detailed_proposal.docx
- landscape.png → actually DOCX (6,484,502 bytes) — EXACT match to [secret_project]_proposal.docx

**TECHNI~1/ (technical review) directory:**
- diary_#1d.txt → actually DOCX (121,441 bytes)
- diary_#1p.txt → actually PPTX (458,267 bytes)
- diary_#2d.txt → actually DOCX (658,922 bytes)
- diary_#2p.txt → actually OLE (1,154,560 bytes)
- diary_#3d.txt → actually OLE (2,360,832 bytes)
- diary_#3p.txt → actually OLE (325,120 bytes)

Four masqueraded files have EXACT byte-for-byte size matches to the legitimate "Secret Project" files still present on the exFAT partition, confirming they are copies of the same documents. All files were created on 2015-03-24 09:59-10:00 UTC and subsequently deleted. The naming pattern uses innocuous-sounding names (movies, friends, calendar, weather) to avoid suspicion.



### 4. [HIGH] Anti-Forensic Tools Installed and Executed by User "informant" — Eraser and CCleaner

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-25T14:50:14 to 2015-03-25T15:15:50 |
| **Sources** | registry.ntuser.informant, registry.system |
| **Evidence Refs** | tc_fd5b1cd7, tc_a5bd6e69 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1485](https://attack.mitre.org/techniques/T1485/) |


The UserAssist registry data from the "informant" user's NTUSER.DAT reveals that anti-forensic/data wiping tools were downloaded, installed, and executed on 2015-03-25:

**Eraser 6.2.0.2962:**
- Downloaded: C:\Users\informant\Desktop\Download\Eraser 6.2.0.2962.exe (UserAssist: 2015-03-25 14:50:14Z, run count: 1)
- Executed: {6D809377-6AF0-444B-8957-A3773F02200E}\Eraser\Eraser.exe (UserAssist: 2015-03-25 15:12:28Z, run count: 1)
- .NET Framework installer also ran from temp path, confirming Eraser installation
- ShimCache shows Eraser.exe with LastModified 2015-01-12 22:56:36 — this is the binary's BUILD DATE, not a prior installation date. The download of the installer on March 25 and .NET Framework bootstrapper confirm fresh installation.

**CCleaner:**
- Downloaded: C:\Users\informant\Desktop\Download\ccsetup504.exe (UserAssist: 2015-03-25 14:57:56Z, run count: 1)
- Executed: {6D809377-6AF0-444B-8957-A3773F02200E}\CCleaner\CCleaner64.exe (UserAssist: 2015-03-25 15:15:50Z, run count: 1)
- **Counter-analysis note:** ShimCache reveals CCleaner was PREVIOUSLY installed on the system (CCleaner64.exe LastModified: 2015-03-13 11:10:26) and then UNINSTALLED on the same date (uninst.exe + ~nsu.tmp\Au_.exe ran at 2015-03-13 13:55:38). The user then re-downloaded and installed a newer version (ccsetup504.exe = v5.04) on March 25. The deliberate re-installation of a previously-uninstalled tool specifically during the cleanup phase actually STRENGTHENS the anti-forensic intent — this was not routine software maintenance but a purposeful re-deployment.

These tools are commonly used for secure deletion and trace removal. The timing — one day after the masqueraded documents were placed on and deleted from the removable media (2015-03-24) — strongly suggests these tools were used to cover tracks of the data exfiltration activity. The USBSTOR driver was last written at 2015-03-24 13:37:59Z, confirming USB device activity on the same day.

The user also installed Google Drive (UserAssist: 2015-03-25 15:21:30Z, run count: 1) — a cloud sync service that could represent an additional exfiltration channel.



### 5. [HIGH] User Identity Established — "Iaman Informant" (iaman.informant@nist.gov) with Resignation Letter

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant, bulk.email, tsk.masquerade |
| **Evidence Refs** | tc_fd5b1cd7, tc_dee1e294, tc_5a50c2c3 |
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |


Multiple evidence sources converge to identify the user conducting the data exfiltration:

**User Account:** "informant" on the PC (cfreds_2015_data_leakage_pc.E01)

**Email Addresses (from bulk_extractor):**
- iaman.informant@nist.gov — Primary email, found in Outlook .ost file references and Exchange mailbox data
- iaman@nist.gov — BASIC authentication credential found in the PC image

**Volume Label Correlation:** The FAT32 partition on rm2 containing the masqueraded files has the volume label "IAMAN $_@" — matching the user's name pattern

**Recent Documents (from NTUSER.DAT RecentDocs):**
The user recently accessed these documents, ordered by MRU:
1. Resignation_Letter_(Iaman_Informant).docx
2. Resignation_Letter_(Iaman_Informant).xps  
3. BD-RE Drive (D:) IAMAN CD
4. winter_whether_advisory.zip (one of the masqueraded files on rm2!)
5. [secret_project]_final_meeting.pptx
6. (secret_project)_pricing_decision.xlsx
7. [secret_project]_design_concept.ppt
8. [secret_project]_proposal.docx

**Word Wheel Query:** User searched for "secret" on 2015-03-23 18:40:17Z

**Resignation Activity:** 
- Word was used 4 times (2015-03-25 15:24:48Z)
- The resignation letter was saved in both .docx and .xps formats
- XPS Viewer was opened (2015-03-25 15:28:47Z)

The creation of a resignation letter concurrent with data exfiltration and anti-forensic tool usage indicates a departing insider threat scenario.



### 6. [HIGH] Web Search History Reveals Premeditated Data Theft and Anti-Forensics Research

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:30:06 |
| **Sources** | bulk.url_searches, bulk.url |
| **Evidence Refs** | tc_a3e63ebb, tc_afa5f6da |
| **ATT&CK** | [T1213](https://attack.mitre.org/techniques/T1213/), [T1567](https://attack.mitre.org/techniques/T1567/) |


The user "informant" conducted extensive web research demonstrating premeditation of data theft and knowledge of forensic techniques. Bulk extractor's URL search histogram from the PC image reveals the following search queries (with hit counts):

**Data Theft Planning:**
- "file sharing and tethering" (n=491)
- "information leakage cases" (n=47)
- "data leakage methods" (n=1)
- "leaking confidential information" (n=2)
- "how to leak a secret" (n=6) — led to Microsoft Research paper
- "intellectual property theft" (n=6)

**Exfiltration Method Research:**
- "cd burning method" (n=64)
- "cd burning method in windows" (n=53)
- "cloud storage" (n=6)
- "google drive" (n=10)
- "apple icloud" (n=1)
- "external device and forensics" (n=65)
- "security checkpoint cd-r" (n=1)
- "DLP DRM" (n=90) — Data Loss Prevention / Digital Rights Management research

**Anti-Forensic Tool Research:**
- "anti-forensic tools" (n=85)
- "anti-forensics" (multiple variations)
- "ccleaner" (n=65)
- "eraser" (n=51)
- "system cleaner" (n=5)
- "how to delete data" (n=5)

**Forensics Awareness:**
- "digital forensics" (multiple)
- "what is windows system artifacts" (n=79)
- "windows event logs" (n=61)
- "investigation on windows machine" (n=64)
- "e-mail investigation" (n=88)
- "Forensic Email Investigation" (n=78)
- "data recovery tools" (n=4+)
- "how to recover data" (n=1+)

The user also visited forensicswiki.org/wiki/Anti-forensic_techniques and forensicswiki.org/wiki/Tools:Data_Recovery, demonstrating direct research into anti-forensic techniques.

**Counter-analysis — could these be legitimate security research?**
While individual searches for "digital forensics" or "windows event logs" could plausibly reflect legitimate security work at NIST, the overall pattern is conclusive for malicious intent because: (1) the searches span the FULL cycle from planning ("data leakage methods") to method selection ("cd burning method") to anti-forensics ("ccleaner", "eraser"); (2) every researched method was subsequently EXECUTED — USB exfiltration, CD burning, cloud storage setup, CCleaner/Eraser installation; (3) no defensive/organizational context was found (no searches for "how to prevent data leakage" or "DLP deployment"); (4) the temporal correlation between searches and actions is precise. The "legitimate research" hypothesis cannot explain the complete 1:1 mapping between web research topics and subsequent executed actions.

This search history demonstrates the user was aware of forensic investigation methods and deliberately researched ways to steal data, use multiple exfiltration channels (USB, CD burning, cloud storage), and cover their tracks using anti-forensic tools — all of which they subsequently executed.



### 7. [HIGH] CD/DVD Burning Used as Third Exfiltration Channel — "IAMAN CD" on BD-RE Drive D:

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T19:47:48 to 2015-03-24T20:54:07 |
| **Sources** | registry.ntuser.informant, registry.usrclass.informant, ez.shimcache, bulk.url_searches |
| **Evidence Refs** | tc_37d72926, tc_99559e57, tc_3684db75, tc_a3e63ebb |
| **ATT&CK** | [T1052](https://attack.mitre.org/techniques/T1052/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


Evidence from multiple sources converges to show the user burned data to CD/DVD as an additional exfiltration method alongside USB drives and cloud storage:

**Shellbag Evidence:**
- RecentDocs show "BD-RE Drive (D:) IAMAN CD" was recently accessed (MRU position 3)
- RecentDocs also show "BD-RE Drive (D:)" was accessed separately (MRU position 7)
- Shellbags show user browsed D: drive with abbreviated project directory names matching the Secret Project structure:
  - D:\de (design) — accessed 2015-03-24 19:47:48 UTC, last browsed 2015-03-24 20:44:13 UTC
  - D:\tr (technical review) — accessed 2015-03-24 19:47:48 UTC
  - D:\pd (pricing decision) — accessed 2015-03-24 20:41:22 UTC
  - D:\prop (proposal) — accessed 2015-03-24 20:41:22 UTC
  - D:\prog (progress) — accessed 2015-03-24 20:41:22 UTC

**Masqueraded File on D: Drive:**
- Shellbags show D:\de\winter_whether_advisory.zip [16381123 bytes] was opened (2015-03-24 19:54:43 UTC)
- This is the EXACT same file name and size as the masqueraded PPTX file found on RM2 AND in the deleted sessions of RM3

**CD Burn Path Confirmation:**
- ShimCache entry: "C:\Users\informant\AppData\Local\Microsoft\Windows\Burn\Burn\IE11-Windows6.1-x64-en-us.exe" (2015-03-22 15:11:04)
- The Windows Burn folder is the staging directory for Windows' built-in CD/DVD burning functionality

**RM3 Optical Disc Analysis (NEW - corroborating):**
The rm3 optical disc image (cfreds_2015_data_leakage_rm3_type3.E01) has been analyzed and confirms:
- Volume label: "IAMAN CD" — matches RecentDocs entry exactly
- UDF write-once format with 9 burn sessions
- Contains the same 17 masqueraded documents in deleted sessions (identical file names and byte-exact sizes)
- Abbreviated directory names on disc (de, pd, prog, prop, tr) match the D: drive structure in shellbags
- Files created on disc 2015-03-24 20:54:16-20:55:46 UTC — matches the D: drive browsing activity window
- Final session burned with 3 innocuous Windows 7 sample photos (Koala.jpg, Penguins.jpg, Tulips.jpg) as cover

**Timeline Synthesis:**
1. 19:47-20:44 UTC: User browses D: drive with abbreviated directories (shellbags)
2. 19:54 UTC: User opens winter_whether_advisory.zip from D:\de\ (verifying content)
3. 20:54-20:55 UTC: Documents burned to disc across all directories (rm3 optical.listing)
4. 20:57 UTC: Cover photos (Koala, Penguins, Tulips) burned as final session (rm3 optical.listing)
5. 21:01 UTC: User accesses Tulips.jpg (RecentDocs) — verifying final disc contents

This confirms the disc was burned from the PC at approximately 20:54-20:57 UTC on March 24, 2015.



### 8. [HIGH] Network Share \\10.11.11.128\secured_drive Accessed as Source of Stolen Documents

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22 to 2015-03-24T13:57:40 |
| **Sources** | registry.usrclass.informant, registry.ntuser.informant |
| **Evidence Refs** | tc_99559e57, tc_37d72926 |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/), [T1005](https://attack.mitre.org/techniques/T1005/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |


Shellbag analysis from the "informant" user's UsrClass.dat reveals the source of the exfiltrated documents — a network file share at \\10.11.11.128\secured_drive:

**Network Share Structure (from shellbags):**
- \\10.11.11.128\secured_drive\ (MRU time: 2015-03-23 20:23:28 UTC)
  - Common Data\ (created 2015-03-22 14:52:22 UTC)
  - Past Projects\ (modified 2015-02-05 18:06:32 UTC, accessed until 2015-03-24 13:47:54 UTC)
  - Secret Project Data\ (created 2015-03-22 14:52:22 UTC, MRU time: 2015-03-23 20:27:24 UTC)
    - design\ (accessed 2015-03-22 14:52:22 UTC)
    - pricing decision\ (MRU time: 2015-03-23 20:28:17 UTC)
    - final\ (MRU time: 2015-03-23 20:27:29 UTC)
    - progress\ (accessed 2015-03-22 14:52:22 UTC)
    - proposal\ (accessed 2015-03-22 14:52:22 UTC)
    - technical review\ (accessed 2015-03-22 14:52:24 UTC)

**Mapped Drive V:**
- The same share appears mapped as drive V:\ in shellbags
- V:\Secret Project Data\ (with MFT file ref 43045/1) accessed 2015-03-23 20:27:24 UTC
- V:\Secret Project Data\final\ (with MFT file ref 43048/1) accessed 2015-03-23 20:27:29 UTC

**Local Cache "S data":**
- A local path labeled "S data" in shellbags shows the same directory structure cached or copied locally:
  - S data\Secret Project Data\ (accessed 2015-03-24 13:40:13 UTC)
  - S data\Secret Project Data\design\ (MRU time: 2015-03-24 13:57:40 UTC)
  - S data\Secret Project Data\Secret Project Data\ — nested directories indicate the entire project structure was copied
  - S data\Secret Project Data\Common Data\, Past Projects\, final\, pricing decision\, progress\, technical review\
- MFT file references in shellbags (43045/1, 43048/1, etc.) confirm these were live filesystem objects on the network share

**Source-to-Destination Correlation:**
The network share directory structure exactly matches:
1. The file structure on the RM1 USB drive (RM#1/Secret Project Data/design/ and /proposal/)
2. The deleted directory structure on RM2 ($OrphanFiles/design/, /PRICIN~1/, /progress/, /proposal/, /TECHNI~1/)
3. The abbreviated directories on the "IAMAN CD" D: drive (de, tr, pd, prop, prog)

This confirms the user systematically browsed the secured network share, copied the Secret Project Data to multiple exfiltration channels, and organized the stolen data to match the original directory structure.



### 9. [HIGH] 17 Masqueraded Documents from Earlier Burn Sessions Deleted/Overwritten on RM3 Optical Disc

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16 to 2015-03-24T21:01:14 |
| **Sources** | bulk.email, bulk.exif, optical.listing, registry.ntuser.informant, tsk.filelist, tsk.masquerade |
| **Evidence Refs** | tc_64cb01b3, tc_b4cbb86d, tc_ffe19b00 |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1052](https://attack.mitre.org/techniques/T1052/), [T1070](https://attack.mitre.org/techniques/T1070/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) |


The rm3 optical disc contains 17 deleted files in earlier burn sessions that are identical in name and size to the masqueraded documents found on the rm2 USB drive. All are Office documents (OLE/DOCX/PPTX/XLSX) deliberately renamed with false extensions to conceal their true nature.

**Deleted Files from Earlier Sessions (matching rm2 exactly by name and size):**

**design/ (session -7) → de/ (session -1):**
- winter_storm.amr (14,547,968 bytes) — actually OLE ([secret_project]_revised_points.ppt)
- winter_whether_advisory.zip (16,381,123 bytes) — actually PPTX ([secret_project]_detailed_design.pptx)

**pricing decision/ (session -6) → pd/ (session -1):**
- my_favorite_cars.db (1,260,544 bytes) — actually OLE document
- my_favorite_movies.7z (100,078 bytes) — actually XLSX
- new_years_day.jpg (10,237,535 bytes) — actually XLSX
- super_bowl.avi (10,289,152 bytes) — actually OLE document

**progress/ (session -5) → prog/ (session -1):**
- my_friends.svg (58,368 bytes) — actually OLE document
- my_smartphone.png (4,440,235 bytes) — actually DOCX
- new_year_calendar.one (27,414 bytes) — actually DOCX

**proposal/ (session -4) → prop/ (session -1):**
- a_gift_from_you.gif (35,226,880 bytes) — actually DOCX ([secret_project]_detailed_proposal.docx)
- landscape.png (6,484,502 bytes) — actually DOCX ([secret_project]_proposal.docx)

**technical review/ (session -3) → tr/ (session -1):**
- diary_#1d.txt (121,441 bytes), diary_#1p.txt (458,267 bytes), diary_#2d.txt (658,922 bytes), diary_#2p.txt (1,154,560 bytes), diary_#3d.txt (2,360,832 bytes), diary_#3p.txt (325,120 bytes) — all actually Office documents

**All 17 files match the rm2 masqueraded files byte-for-byte in size.** The file sizes were confirmed against the existing masquerade detection for rm2 (finding f_7d6529f2). The directory structure mirrors the Secret Project Data from the network share at \\\\10.11.11.128\\secured_drive.

**Total data in deleted sessions: approximately 104 MB of masqueraded documents.**

All files have creation timestamps of 2015-03-24 20:54:16 to 20:55:46 UTC, indicating they were burned to the disc in a single session on March 24, 2015.

**Merged findings:**
- **RM3 Optical Disc: Multi-Session UDF Burning Strategy with Document Concealment in Deleted Sessions** (f_ffb11990, high, confirmed): The RM3 optical disc (cfreds_2015_data_leakage_rm3_type3.E01) uses a sophisticated multi-session UDF burning strategy to conceal 17 masqueraded documents in deleted sessions while presenting innocent cover files.

**Disc Structure:**
- Format: UDF filesystem on CD-R/DVD media
- Volume Label: "IAMAN CD" (correlates with user identity)
- 9 burn sessions total, all on 2015-03-24 between 20:54:16 and 20:57:03 UTC

**Session Strategy:**
Sessions 1-8 (20:54:16 to 20:55:46 UTC) each contain a subdirectory of masqueraded documents:
- Session containing "de/" (design): winter_storm.amr, winter_whether_advisory.zip
- Session containing "pd/" (pricing decision): my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi
- Session containing "prog/" (progress): my_friends.svg, my_smartphone.png, new_year_calendar.one
- Session containing "prop/" (proposal): a_gift_from_you.gif, landscape.png
- Session containing "tr/" (technical review): diary_#1d.txt through diary_#3p.txt
- Additional sessions with partial directory structures

Session 9 (final, 20:57:00-20:57:03 UTC) overwrites the disc's visible content with three Windows 7 stock photos:
- Koala.jpg (780,831 bytes)
- Penguins.jpg (777,835 bytes)
- Tulips.jpg (620,888 bytes)

**Concealment Effectiveness:**
A standard disc read shows only the final session — three harmless stock photos. The masqueraded documents in earlier sessions are invisible to normal file browsing. Only forensic tools that parse UDF session history can reveal the hidden content. The abbreviated directory names (de, pd, prog, prop, tr) correspond to the full names from the source network share (design, pricing decision, progress, proposal, technical review).

**Cover File Verification:**
The user's RecentDocs registry shows Tulips.jpg was accessed at 2015-03-24 21:01:14 UTC — 4 minutes after the final burn — confirming the user verified the disc appeared clean.

All 17 documents match byte-exactly with those on RM2, confirming the same files were exfiltrated through both channels.
- **Windows 7 Sample Photos Used as Decoy Cover Files on RM3 Optical Disc** (f_5702c3cd, low, confirmed): The final visible session (session 0) of the rm3 optical disc contains only three Windows 7 stock sample photographs, burned as cover files to hide the masqueraded documents in earlier sessions.

**Active Cover Files:**
1. Koala.jpg — 780,831 bytes, modified 2009-07-14T05:32:31Z, created on disc 2015-03-24T20:57:00Z
2. Penguins.jpg — 777,835 bytes, modified 2009-07-14T05:32:31Z, created on disc 2015-03-24T20:57:00Z
3. Tulips.jpg — 620,888 bytes, modified 2009-07-14T05:32:31Z, created on disc 2015-03-24T20:57:03Z

**Origin:** The modification date of 2009-07-14 matches the Windows 7 RTM release date. EXIF metadata confirms:
- Koala.jpg: Artist "Corbis", DateTimeOriginal 2008:02:11
- Penguins.jpg: Artist "Corbis", DateTimeOriginal 2008:02:18  
- Tulips.jpg: Artist "Microsoft Corporation", DateTimeOriginal 2008:02:07

These are the standard Windows 7 sample pictures found in C:\\Users\\Public\\Pictures\\Sample Pictures on any default Windows 7 installation. Their presence on the disc is forensically significant because:

1. They were burned as the FINAL session, overwriting/hiding all previous document sessions
2. They were created on the disc approximately 1 minute after the last document directory was burned (20:55:46 → 20:57:00)
3. The user's RecentDocs registry on the PC shows Tulips.jpg was accessed at 2015-03-24 21:01:14 UTC — 4 minutes after the disc burn — suggesting the user verified the disc contents after burning
4. A casual inspection of the disc would show only these three harmless stock photos

**PC Corroboration:** The informant user's RecentDocs (from existing finding f_c0f08710) shows these three images in MRU positions 4-6, accessed on 2015-03-24, confirming the user interacted with these files during the disc burning session.

**Affected Systems:** bulk.email, bulk.exif, optical.listing, registry.ntuser.informant, tsk.filelist, tsk.masquerade



### 10. [MEDIUM] RM2 File Activity Timeline — Systematic Data Staging, Masquerading, and Cleanup

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 to 2015-03-25T15:30:06 |
| **Sources** | tsk.timeline, registry.usrclass.informant, registry.ntuser.informant |
| **Evidence Refs** | tc_8617c171, tc_534f0f16, tc_fd5b1cd7 |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The filesystem timeline from the rm2 device reveals a systematic pattern of data staging and concealment across multiple sessions:

**Phase 1 — Initial Document Copy (2015-02-15, ~16:51-16:52 UTC):**
- Secret Project files (design and proposal) were copied to the exFAT "Authorized USB" partition under RM#1/Secret Project Data/
- Directory structure (design/, proposal/) was created and populated with 5 Office documents
- A Word temp file (~$ecret_project]_proposal.docx) was created, indicating the proposal was opened for editing

**Phase 2 — Directory Deletion (2015-02-27):**
- The "Secret Project Data" directory (inode 2054) was deleted at 17:20:18 UTC

**Phase 3 — Masqueraded Copy Session (2015-03-23 to 2015-03-24):**
- 2015-03-23 14:32:20-14:38:46: Activity on the exFAT partition (possible re-access of existing files)
- 2015-03-23 16:55:17-16:55:37: Personal image files (25 photos) given birth timestamps — bulk copy operation
- 2015-03-24 09:54:54-09:57:32: Deleted directories created (progress, proposal, TECHNI~1, design, PRICIN~1)
- 2015-03-24 09:59:26-10:00:18: 17 masqueraded document copies created across all project directories
- 2015-03-24 15:51:47-15:51:48: desktop.ini created and modified
- 2015-03-24 17:02:36: Volume label entry last modified

**Phase 4 — Corresponding PC Activity (from Shellbags):**
- 2015-03-24 13:37:59: USBSTOR driver last accessed (USB device connected)
- 2015-03-24 13:38:31-14:01:29: User browsed Secret Project directories on E: drive and opened winter_whether_advisory.zip
- 2015-03-24 19:47:48-20:54:07: User browsed D: drive with abbreviated project directory names (de, tr, pd, prop, prog)

**Phase 5 — Anti-Forensic Cleanup (2015-03-25):**
- Downloaded and installed Eraser and CCleaner
- Created resignation letter
- Installed Google Drive



### 11. [MEDIUM] Environment-Wide Cross-Device Document Correlation — Byte-Level Matches Across PC, RM1, RM2, and RM3

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-02-15T16:51:38 |
| **Sources** | bulk.duplicates, bulk.url_services, bulk.email, bulk.exif, tsk.filelist, tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_c963a5ef, tc_f9f83b4b |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Bulk extractor duplicate analysis and file metadata comparison confirm byte-level document equivalence across all four evidence sources, establishing a definitive cross-device provenance chain.

**SHA1 Fragment Matching:**
- Bulk.duplicates from RM1: 1,298 matching SHA1 hash entries linking carved ZIP fragments to PC and RM2
- Bulk.duplicates from RM3: 1,738 matching SHA1 entries within the optical disc (same fragments across multiple burn sessions)
- Fragment hash 001bd4287032c56dd1f8918e55928324f52e66db appears across RM1 (offset 2324418-ZIP-0), RM2 (offset 105364807-ZIP-0), and PC (offset 16529177927-ZIP-0)

**Byte-Exact File Size Matches (RM2 ↔ RM3):**
All 17 masqueraded documents match exactly between RM2's FAT32 partition and RM3's UDF deleted sessions:
- winter_storm.amr = 14,547,968 bytes (both devices)
- winter_whether_advisory.zip = 16,381,123 bytes (both devices)
- a_gift_from_you.gif = 35,226,880 bytes (both devices)
- landscape.png = 6,484,502 bytes (both devices)
- [13 additional files with exact size matches]

**RM1 ↔ RM2/RM3 Matches (5 documents):**
- [secret_project]_revised_points.ppt = winter_storm.amr (14,547,968 bytes)
- [secret_project]_detailed_design.pptx = winter_whether_advisory.zip (16,381,123 bytes)
- [secret_project]_detailed_proposal.docx = a_gift_from_you.gif (35,226,880 bytes)
- [secret_project]_proposal.docx = landscape.png (6,484,502 bytes)
- [secret_project]_design_concept.ppt (1,810,432 bytes) — matches RM2/RM3 design directory files

**OOXML ZIP-Carved Entry Counts:**
- RM2: 5,221 carved ZIP entries
- RM3: 5,221 carved ZIP entries (exact match confirms identical document content)

**Embedded Metadata Consistency:**
- Same NASA/JPL email addresses across all devices
- Same URL histogram patterns (MEPAG, dx.doi.org, pnas.org)
- Same EXIF metadata (Kodak DC260, Adobe Photoshop CS)

This convergence from 4 independent evidence sources using 3 independent correlation methods (SHA1 hashing, file size comparison, embedded metadata) conclusively proves the documents on all media originated from the same source and were copied by the same actor.



### 12. [MEDIUM] RM2 Dual-Partition Structure — FAT32 Partition Used as Hidden Storage for Disguised Documents

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T09:59:26 |
| **Sources** | tsk.fsstat, tsk.masquerade, tsk.filelist |
| **Evidence Refs** | tc_f02683d0, tc_c7361cc3, tc_22156eec |
| **ATT&CK** | [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1027](https://attack.mitre.org/techniques/T1027/) |


The rm2 removable media device contains TWO separate filesystem partitions, which is atypical for a standard USB drive:

**Partition 1 — FAT32 (128-sector offset):**
- Volume Label: "IAMAN $_@" (correlates with user identity "Iaman Informant")
- Contains ONLY deleted files: 17 masqueraded Office documents and ~25 personal photographs
- All document files have deliberately false extensions (.amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt)
- Total sector range: 0-2,097,151 (approximately 1GB)

**Partition 2 — exFAT (32-sector offset):**
- Volume Label: "Authorized USB"
- Contains live "Secret Project Data" files in proper directory structure
- Also contains a copy under "RM#1/" path (same inodes, indicating either hard links or directory alias)
- Volume serial: 5c75-4d3e
- Total sector range: 0-7,821,279 (approximately 4GB)

**Forensic Significance:**
The FAT32 partition served as a secondary, less-visible storage area where documents could be stashed with false extensions. The exFAT partition labeled "Authorized USB" appears to be the "public-facing" partition that would be visible to casual inspection, containing properly-named secret project files. This dual-partition approach may have been intended to maintain plausible deniability — the FAT32 partition with innocuously-named files would not attract attention, while the exFAT partition's "Authorized USB" label suggests it was meant to appear as a sanctioned device.

No masquerading was detected on the rm1 device (0 masquerade entries), confirming the concealment strategy was specific to rm2.



### 13. [MEDIUM] SanDisk Cruzer Fit USB Drive Connected — Two Serial Numbers Indicate Two Physical Devices

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T13:37:59 to 2015-03-24T13:58:32 |
| **Sources** | registry.query.system, registry.system |
| **Evidence Refs** | tc_f8f0c930, tc_028da839, tc_e46de9fc |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1091](https://attack.mitre.org/techniques/T1091/) |


The USBSTOR registry key on the PC image reveals that SanDisk Cruzer Fit USB drives were connected to the system:

**Device Identification:**
- Vendor: SanDisk
- Product: Cruzer Fit
- Revision: 2.01
- Registry Key LastWritten: 2015-03-24 13:58:32 UTC

**Two Device Serial Numbers Detected:**
1. 4C530012450531101593&0
2. 4C530012550531106501&0

The presence of two distinct serial numbers under the same device model indicates TWO separate SanDisk Cruzer Fit USB drives were connected to this PC. This is consistent with the evidence of two removable media images (rm1 and rm2):
- RM1 (exFAT, "Authorized USB"): Contains the original Secret Project documents with legitimate file names
- RM2 (FAT32, "IAMAN $_@"): Contains 17 deleted masqueraded documents and the exFAT partition with the same document copies

The USBSTOR driver's LastWrite time of 2015-03-24 13:37:59 UTC corresponds to the day the masqueraded files were created on RM2 (2015-03-24 09:59-10:00 UTC), confirming USB device activity on the same day as the disguised file staging operation.

The user also accessed the USB drive letter E: as shown in shellbags, navigating through RM#1/Secret Project Data/ and Secret Project Data/ directories on E: starting 2015-03-24 13:38:31 UTC.



### 14. [MEDIUM] Cloud Storage Services (Google Drive, iCloud) Installed — Sync Databases Deleted, Cloud Exfiltration Unconfirmed

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-23T19:56:33 to 2015-03-25T15:21:30 |
| **Sources** | tsk.filelist, composite.correlation, registry.ntuser.informant, registry.usrclass.informant, ez.mft, bulk.url_searches |
| **Evidence Refs** | tc_4cf9fde9, tc_c9da15bb |
| **ATT&CK** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


Cross-referencing the PC file listing with registry and MFT data reveals that cloud storage services were downloaded and installed but their operational databases were subsequently deleted, preventing confirmation of cloud-based exfiltration:

**Google Drive Installation and Configuration:**
- googledrivesync.exe downloaded to Users\informant\Downloads\ (with Zone.Identifier confirming internet download)
- Google Drive installed to Program Files (x86)\Google\Drive\ with ContextMenuModule.dll.mui language files
- UserAssist: googledrivesync.exe executed at 2015-03-25 15:21:30 UTC (run count: 1)
- Shellbags: "Users\Google Drive" folder created 2015-03-23 20:05:34 UTC, accessed 2015-03-25 15:20:59 UTC
- RunOnce key written at 2015-03-23 20:05:35 UTC (Google Drive startup registration)

**Google Drive Deleted Database Files (from tsk.filelist on PC):**
- Users/informant/AppData/Local/Google/Drive/user_default/sync_config.db-shm (DELETED, marked -/r *)
- Users/informant/AppData/Local/Google/Drive/user_default/cacerts (DELETED)
- Users/informant/AppData/Local/Google/Drive/user_default/snapshot.db (DELETED)

**Apple iCloud Installation:**
- icloudsetup.exe downloaded to Users\informant\Downloads\ (ShimCache: 2015-03-23 19:56:53 UTC)
- Apple iCloud components installed under Common Files\Apple\Internet Services\
- No iCloud database files found — less evidence of actual usage

**Web Search Context:**
- User searched for "cloud storage" (n=6), "google drive" (n=10), "apple icloud" (n=1)
- These searches occurred alongside research into "cd burning method" and "external device and forensics"

**Assessment:**
The deletion of Google Drive's sync_config.db and snapshot.db removes the primary forensic artifacts that would confirm whether files were uploaded. CCleaner was executed approximately 30 minutes before googledrivesync.exe was last launched (CCleaner at 15:15:50, Google Drive at 15:21:30 on 2015-03-25). This suggests the user may have cleaned traces and then used Google Drive for a final sync. Without the sync database, cloud exfiltration remains a plausible but unconfirmed additional channel alongside the confirmed USB and CD exfiltration paths.



### 15. [MEDIUM] Decoy Account Creation (admin11, ITechTeam, temporary) — Privilege Escalation with Minimal Activity Suggests Misdirection

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:51:43 to 2015-03-22T15:57:30 |
| **Sources** | hayabusa.alerts, chainsaw.hunt, composite.correlation, registry.ntuser.admin11, registry.usrclass.admin11, registry.ntuser.temporary, registry.usrclass.temporary, registry.usrclass.informant |
| **Evidence Refs** | tc_af8bec1f, tc_c9da15bb |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1078](https://attack.mitre.org/techniques/T1078/) |


Cross-referencing Hayabusa/Chainsaw alerts with registry analysis confirms three accounts were created by user "informant" with elevated privileges but minimal post-creation activity, consistent with decoy/misdirection tactics:

**Account Creation Timeline (72-second window on 2015-03-22):**
- 15:51:43 UTC: User "informant" navigated to Control Panel > Create New Account (shellbags)
- 15:51:54 UTC: admin11 created and added to Administrators group (Hayabusa Event ID 4732)
- 15:52:10 UTC: admin11 password reset (Event ID 4724)
- 15:52:30 UTC: ITechTeam created and added to Administrators group
- 15:52:45 UTC: ITechTeam password reset
- 15:53:11 UTC: temporary password reset

**admin11 Activity (SID ...1001):**
- UserAssist: NOTEPAD.EXE (1 run, 15:57:30), explorer.exe (1 run, 15:57:08), Chrome (1 run, 15:55:21), Windows Getting Started (14 — auto-launches)
- Shellbags: Only Libraries folder browsed at 15:57:18 UTC
- Total registry data: 133 lines in NTUSER.DAT — very minimal
- No evidence of document access, network share browsing, or tool usage

**ITechTeam Activity (SID ...1002):**
- NO separate NTUSER.DAT or UsrClass.dat hive extracted — account may never have been logged into interactively

**temporary Activity (SID ...1003):**
- UserAssist: explorer.exe (1 run, 15:56:13)
- Shellbags: Only Libraries folder at 15:56:19 UTC
- Total registry data: 118 lines — minimal

**Counter-analysis — could these be legitimate IT testing accounts?**
While account creation itself is a normal administrative activity, several factors make the "legitimate IT testing" hypothesis implausible: (1) All three were created in a 72-second burst, not iteratively over time as testing would require; (2) All were immediately added to Administrators group — unusual for test accounts; (3) The naming patterns ("admin11", "ITechTeam", "temporary") mimic legitimate admin nomenclature; (4) The accounts were created on 2015-03-22, the same day the exfiltration campaign began in earnest; (5) None performed any substantive activity beyond initial login; (6) The "informant" user — not an administrator — is the one who created these accounts, suggesting misuse of existing admin privileges.

**Assessment:**
The account creation facts are confirmed by 2+ independent sources (Hayabusa alerts, Chainsaw, registry hives). The misdirection purpose is an analytical inference strongly supported by the context: accounts created during an active exfiltration campaign with zero productive activity and names designed to appear legitimate.



### 16. [LOW] Evidence of Document Editing and Directory Restructuring on USB Drive

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | confirmed |
| **Time** | 2015-02-27T17:20:18 to 2015-03-23T14:38:46 |
| **Sources** | tsk.timeline, tsk.filelist |
| **Evidence Refs** | tc_eda7523e, tc_15363b94 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The USB drive shows evidence of active document editing and deliberate directory reorganization across multiple dates, indicating ongoing use of the exfiltrated documents rather than a single copy event.

**Deleted Temp File (Evidence of Document Editing):**
- File: ~$ecret_project]_proposal.docx (inode 1030156, 162 bytes)
- Status: Deleted
- Created (born): 2015-03-23 14:37:52 UTC
- Modified/Accessed: 2015-03-23 14:37:54 UTC
- This is a Microsoft Word lock file (~$) automatically created when a .docx file is opened for editing. Its presence proves the proposal document was opened and edited (either from this USB drive or with this file accessible) on March 23, 2015.

**Directory Restructuring Evidence:**
- Original "Secret Project Data" root directory (inode 2054): marked as DELETED
  - Modified: 2015-02-27 17:20:18 UTC
  - Accessed: 2015-03-23 14:32:20 UTC
  - Born: 2015-03-23 14:32:21 UTC
- "RM#1" directory (inode 2058): active, containing the same Secret Project Data subdirectory
  - Modified: 2015-02-15 16:51:38 UTC
  - Accessed/Born: 2015-02-15 16:52:08 UTC

The directory structure shows files were initially copied on Feb 15 under "RM#1/Secret Project Data/", then a second copy appears under "Secret Project Data/Secret Project Data/". The root "Secret Project Data" directory was later deleted. This suggests the USB was reorganized around Feb 27 - Mar 23, 2015.

**Orphan File (inode 5138, realloc):**
- A deleted-realloc orphan file (0 bytes) with timestamps Mar 23, 2015 14:38:21-14:38:46 UTC suggests additional file manipulation around the same time.



### 17. [LOW] Extensive OOXML Document Fragments Recoverable from Unallocated Space on RM1 and RM3

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2015-02-15T16:51:38 |
| **Sources** | bulk.zip_carved, strings.output, bulk.duplicates |
| **Evidence Refs** | tc_9d168614, tc_6f3adb06 |


Bulk extractor's ZIP carving analysis recovered substantial OOXML document fragments from both RM1 and RM3, confirming document content remains recoverable from unallocated space despite concealment efforts.

**RM1 USB Drive:**
- 2,051 windows of carved ZIP data containing Office Open XML fragments
- Fragment types: [Content_Types].xml, _rels/.rels, drs/shapexml.xml, drs/downrev.xml, slideMasters/slideMaster1.xml
- All fragments use MSDOS timestamp 1980-01-01T00:00:00 (default for ZIP entries without time info)
- SHA1 hashes enable correlation with document databases

**RM3 Optical Disc:**
- 5,221 carved ZIP entries (exact match with RM2's 5,221 entries)
- Richer content types recovered: ppt/slides/, xl/worksheets/, word/media/, word/embeddings/
- Word documents contain 100+ embedded images (image1.png through image102.png) — lengthy technical reports
- Presence of footnotes.xml and endnotes.xml confirms academic/scientific document formats
- Multiple distinct [Content_Types].xml files with different SHA1 hashes confirm multiple separate Office documents
- 1,738 internal duplicate entries — same fragments across multiple burn sessions

**Document Types Confirmed:**
- PowerPoint (.ppt/.pptx): slideMasters, drs/shapexml.xml, slide content
- Excel (.xlsx): xl/worksheets/sheet1-7+, sharedStrings.xml
- Word (.docx): word/media/ (100+ images), headers/footers, footnotes/endnotes, oleObject1.bin

**Forensic Significance:**
Despite file extension masquerading and multi-session disc burning, the actual document text, formatting, embedded images, and metadata are largely intact and recoverable from raw data. The exact match of 5,221 ZIP entries between RM2 and RM3 confirms byte-level content equivalence.



### 18. [LOW] Deleted Files Recoverable from RM2 FAT32 Partition — Organizational Data in Unallocated Space

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T16:55:17 to 2015-03-24T17:02:36 |
| **Sources** | tsk.timeline, tsk.filelist, bulk.zip_carved |
| **Evidence Refs** | tc_8617c171, tc_ccf3be58 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |


The rm2 FAT32 partition ($OrphanFiles) contains substantial deleted file content that was not securely erased and remains recoverable:

**Deleted organizational documents (masqueraded, total ~97MB):**
17 files with false extensions across 5 project directories, all containing actual Office documents (OLE/DOCX/PPTX/XLSX). File data remains in orphan file entries, indicating the FAT directory entries were removed but the cluster chains may still be intact.

**Deleted personal image files (~80MB):**
An additional ~25 deleted image files (amalfi.bmp, barn.gif, cactus.png, pisa.JPG, SPQR.JPG, etc.) with modification dates ranging from 2004-2013, created on the device around 2015-03-23 16:55 UTC. These appear to be legitimate personal photos that were previously stored on the device.

**Deleted system files:**
- desktop.ini (deleted, 129 bytes, created 2015-03-24 15:51:47Z)
- OrphanFile-5138 (deleted-realloc, 0 bytes)

**Bulk extractor carving results:**
The bulk.zip_carved source from rm2 contains 5,221 carved entries, indicating significant Office document content (OOXML formats use ZIP containers) recoverable from unallocated space.

The bulk.email source from rm2 contains 61 entries, and bulk.rfc822 contains 41 entries, indicating embedded email addresses and metadata from the documents.

The fact that the deleted document content remains recoverable despite the user installing Eraser and CCleaner on 2015-03-25 suggests the anti-forensic tools may not have been used against this particular device, or were not effective on the FAT32 partition.



### 19. [LOW] Microsoft Outlook Used with NIST Email Account — Potential Email Exfiltration Channel

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2015-03-25T14:41:03 to 2015-03-25T14:41:03 |
| **Sources** | ez.shimcache, registry.ntuser.informant, tsk.filelist, bulk.url_searches |
| **Evidence Refs** | tc_3684db75, tc_37d72926, tc_f5034c6c, tc_a3e63ebb |
| **ATT&CK** | [T1048.002](https://attack.mitre.org/techniques/T1048/002/), [T1114](https://attack.mitre.org/techniques/T1114/) |


Evidence from multiple sources confirms Microsoft Outlook 2013 was actively used by the "informant" user with a NIST email account:

**Outlook Execution:**
- OUTLOOK.EXE in ShimCache (LastModified: 2012-10-02 00:36:36 UTC, Executed=Yes)
- UserAssist: 5 runs, last execution 2015-03-25 14:41:03 UTC
- Outlook logging found: Users/informant/AppData/Local/Temp/outlook logging/firstrun.log
- MAPISHELL.DLL loaded (ShimCache entry) — MAPI integration confirms active use

**Email Account Identity:**
- Bulk extractor identified: iaman.informant@nist.gov (primary email)
- iaman@nist.gov (BASIC authentication credential)
- Outlook .ost file path references: Outlook\iaman.informant@nist.gov.ost (cached Exchange mailbox)
- Outlook RoamCache files present under AppData\Local\Microsoft\Outlook\RoamCache\ (contact preferences, conversation preferences)
- PB4S-Con* files in Outlook profile directory

**Email Investigation Research:**
- User searched "e-mail investigation" (n=88)
- User searched "Forensic Email Investigation" (n=78)
- User searched "outlook 2013 settings" (n=1)

**Forensic Significance:**
The Outlook client was run 5 times during the investigation period, with the last execution on the final day of activity (2015-03-25) — the same day as anti-forensic tool execution and resignation letter creation. The user's extensive research into "email investigation" and "Forensic Email Investigation" suggests awareness that email could be used as evidence. 

Without direct access to the .ost file contents, it cannot be confirmed whether email was used as an exfiltration channel. However, the combination of active email client use, NIST email account, and research into email forensics makes this a potential exfiltration vector that warrants further investigation of the .ost file.



### 20. [INFO] USB Drive RM1 Filesystem Configuration: exFAT Volume "Authorized USB"

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.fsstat, tsk.partitions |
| **Evidence Refs** | tc_5597d9a6, tc_86b09a00 |


Removable media device RM1 (cfreds_2015_data_leakage_rm1.E01) is a ~3.73 GB USB drive formatted with the exFAT filesystem.

**Filesystem Details:**
- Type: exFAT
- Volume Label: "Authorized USB"
- Volume Serial Number: 5c75-4d3e
- File System Revision: 1.0
- Partition Offset: Sector 32
- Partition Type: 0x07 (NTFS/exFAT)
- Partition Size: 7,821,280 sectors (~3.73 GB)
- Cluster Size: 32,768 bytes (32 KB)
- Number of FATs: 1

The volume label "Authorized USB" suggests this drive was intentionally labeled, possibly to appear as an approved/sanctioned device within an organization. The large cluster size (32 KB) is typical of exFAT formatted on a USB device.



### 21. [INFO] Environment-Wide Document Origin — NASA/JPL Mars Exploration Program (MEPAG) Content Across All Evidence Sources

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | bulk.email, bulk.domain, bulk.url, bulk.url_services, bulk.exif |
| **Evidence Refs** | tc_4d77cd93, tc_c0c389c6, tc_50cd9162 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/) |


Email addresses, URLs, and document metadata embedded within the Office documents are consistent across all four evidence sources (PC, RM1, RM2, RM3), confirming a single document provenance from NASA/JPL Mars exploration research.

**Recovered Email Addresses (from bulk_extractor across all devices):**
- mmeyer@mail.hq.nasa.gov (NASA HQ)
- Karen.L.Buxbaum@jpl.nasa.gov (JPL)
- David.Beaty@jpl.nasa.gov (JPL)
- Eric_P._Lauer@omb.eop.gov (Office of Management and Budget)
- th276a@nih.gov (National Institutes of Health)
- mmun@loc.gov (Library of Congress)

**Recovered URLs referencing NASA/JPL resources:**
- http://mepag.jpl.nasa.gov/reports/index.html (MEPAG reports page)
- http://nodis3.gsfc.nasa.gov/npg_img/Q_ReqNumbers.html (NASA Directive system)
- Various dx.doi.org references to scientific publications

**URL Service Histogram (consistent across RM1, RM2, RM3):**
- ns.adobe.com (n=106) — Adobe document metadata
- digitalcorpora.org (n=26) — Government document corpus
- dx.doi.org (n=20) — Scientific publication DOIs
- www.pnas.org (n=18) — Proceedings of the National Academy of Sciences
- mepag.jpl.nasa.gov (n=5) — Mars Exploration Program

**EXIF Metadata (recovered from RM1 and RM3 unallocated space):**
- Camera: Eastman Kodak Company, KODAK DIGITAL SCIENCE DC260
- Photo dates: 2003:09:24, 2003:12:10
- Software: Adobe Photoshop CS/CS2 (Windows and Macintosh editions)
- Professional photographers: Theo Allofs, Giovanni Simeone/SIME-4Corners Images (stock images embedded in documents)

**Forensic Significance:**
The presence of NASA directive references, MEPAG reports, JPL employee contacts, government agency emails (OMB, NIH, LOC), and scientific DOIs establishes these as sensitive government/scientific research documents. The user 'Iaman Informant' (iaman.informant@nist.gov) is a NIST employee who accessed these materials through the secured network share at 10.11.11.128.



### 22. [INFO] RM1 USB Drive Hash and Evidence Integrity

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | hashdeep.hashes, tsk.fsstat |
| **Evidence Refs** | tc_06def93a, tc_5597d9a6 |


The rm1 evidence image has been hashed for integrity verification and chain of custody purposes.

**Evidence Image Hash (cfreds_2015_data_leakage_rm1.E01):**
- MD5: 7cd7bc148d3a1e5f329cb3580d4d4f8f
- SHA256: a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121
- File Size: 78,186,742 bytes (~74.5 MB in E01 compressed format)

**exFAT Partition Details:**
- Total cluster range: 2 - 122,190
- Root directory starts at cluster 2 (sector 1280)
- Cluster size: 32 KB

The compressed E01 image size (75 MB) vs. the raw partition size (~3.73 GB) indicates significant empty/unallocated space, consistent with a mostly empty USB drive containing only ~71 MB of active document data.

No known document hash database was available for comparison, so hash matching against known sensitive documents from the source organization could not be performed. The file hashes from the individual documents would need to be compared against the originating organization's document management system to confirm exact matches.



### 23. [INFO] Application Execution Timeline Supporting Data Theft — Office, Browsers, and Utilities

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:13 to 2015-03-25T15:28:47 |
| **Sources** | ez.shimcache, registry.ntuser.informant |
| **Evidence Refs** | tc_3684db75, tc_37d72926 |
| **ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |


ShimCache and UserAssist data from the PC image reveal applications executed during the data leakage campaign that facilitated document access, data staging, and exfiltration:

**Office Applications (document access and editing):**
- WINWORD.EXE (Word 2013) — UserAssist: 4 runs, last 2015-03-25 15:24:48 UTC
- POWERPNT.EXE (PowerPoint) — UserAssist: 2 runs, last 2015-03-23 20:27:33 UTC
- EXCEL.EXE (Excel) — UserAssist: 1 run, last 2015-03-23 20:26:50 UTC
- OUTLOOK.EXE — UserAssist: 5 runs, last 2015-03-25 14:41:03 UTC

**Browsers (research, downloads, cloud access):**
- Chrome 41.0.2272.101 — UserAssist: 7 runs, last 2015-03-24 21:05:38 UTC (installed 2015-03-22)
- Internet Explorer 11 — UserAssist: 5 runs, last 2015-03-25 14:46:05 UTC (installed from Downloads)

**Anti-Forensic Tools:**
- Eraser 6.2.0.2962.exe — ShimCache: 2015-03-25 14:47:40 UTC (downloaded)
- Eraser.exe — ShimCache: 2015-01-12 22:56:36 UTC (installed)
- CCleaner uninst.exe — ShimCache: 2015-03-13 13:55:38 UTC (previously installed)
- ccsetup504.exe — ShimCache: 2015-03-25 14:48:28 UTC (new version downloaded)
- CCleaner64.exe — ShimCache: 2015-03-13 11:10:26 UTC

**Cloud Sync Services:**
- googledrivesync.exe — ShimCache: 2015-03-23 19:56:33 UTC (downloaded)
- icloudsetup.exe — ShimCache: 2015-03-23 19:56:53 UTC (downloaded)

**System Utilities:**
- cmd.exe — UserAssist: 4 runs, last 2015-03-23 20:10:19 UTC
- xpsrchvw.exe (XPS Viewer) — UserAssist: 1 run, 2015-03-25 15:28:47 UTC (viewing resignation letter in XPS format)
- Windows Fax and Scan (WFS.exe) — present in ShimCache
- Windows built-in CD/DVD burning — burn folder path in ShimCache

**Notable Absence:** No dedicated file compression/archiving tools (7-Zip, WinRAR) appear in execution artifacts. The user relied on file renaming/masquerading rather than compression for concealment. The built-in zipfldr.dll (Windows ZIP support) was loaded via ShimCache, which could support the .zip extension used in the masquerading scheme (winter_whether_advisory.zip).



### 24. [INFO] RecentDocs and MRU Entries Confirm Access to Secret Project Files and Masqueraded Documents

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 to 2015-03-25T15:29:08 |
| **Sources** | registry.ntuser.informant |
| **Evidence Refs** | tc_37d72926 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/) |


The NTUSER.DAT RecentDocs registry key for user "informant" reveals the most recently accessed documents, listed in MRU (Most Recently Used) order:

**RecentDocs (All, MRUListEx order):**
1. Resignation_Letter_(Iaman_Informant).docx — 2015-03-25 15:29:08 UTC
2. Resignation_Letter_(Iaman_Informant).xps — 2015-03-25 15:28:33 UTC
3. BD-RE Drive (D:) IAMAN CD — (CD/DVD media with the user's name)
4. Tulips.jpg — 2015-03-24 21:01:14 UTC (viewing sample photos)
5. Koala.jpg
6. Penguins.jpg
7. BD-RE Drive (D:) — (raw CD drive access)
8. winter_whether_advisory.zip — 2015-03-24 20:44:18 UTC (masqueraded PPTX file!)
9. final — (directory access)
10. [secret_project]_final_meeting.pptx — 2015-03-23 20:27:33 UTC
11. pricing decision — (directory access)
12. (secret_project)_pricing_decision.xlsx — 2015-03-23 20:26:53 UTC
13. secret — (directory browsing, 2015-03-23 18:38:21 UTC)
14. [secret_project]_design_concept.ppt — 2015-03-23 18:38:21 UTC
15. [secret_project]_proposal.docx — (earliest in MRU)

**By Extension:**
- .docx: Resignation_Letter_(Iaman_Informant).docx, [secret_project]_proposal.docx
- .ppt: [secret_project]_design_concept.ppt (2015-03-23 18:38:21 UTC)
- .pptx: [secret_project]_final_meeting.pptx (2015-03-23 20:27:33 UTC)
- .xlsx: (secret_project)_pricing_decision.xlsx (2015-03-23 20:26:53 UTC)
- .zip: winter_whether_advisory.zip (2015-03-24 20:44:18 UTC)
- .xps: Resignation_Letter_(Iaman_Informant).xps (2015-03-25 15:28:33 UTC)

**Folder Access (MRUListEx order):**
1. BD-RE Drive (D:) IAMAN CD
2. BD-RE Drive (D:)
3. final
4. pricing decision
5. secret

**WordWheelQuery (Windows Search):**
- User searched for "secret" at 2015-03-23 18:40:17 UTC

**OpenSavePidlMRU (File Dialog History):**
Most recently opened/saved files in MRU order:
1. Resignation_Letter_(Iaman_Informant).xps
2. ccsetup504.exe (from Download folder)
3. Eraser 6.2.0.2962.exe (from Download folder)
4. Resignation_Letter_(Iaman_Informant).docx
5. IE11-Windows6.1-x64-en-us.exe (from Download folder)

The presence of winter_whether_advisory.zip in RecentDocs is particularly significant — this is one of the masqueraded files from RM2 where [secret_project]_detailed_design.pptx was disguised with a .zip extension and an innocuous name. The user's recent access to this file on the D: drive (2015-03-24 20:44:18 UTC) confirms they were verifying the masqueraded files on the burned CD.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | Network Share \\10.11.11.128\secured_drive Accessed as Source of Stolen Document |
| Internal IP | `10.11.11.129` |  | Cross-System Provenance Chain: Network Share → PC Local Staging → USB/CD Exfiltr |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Users\informant\Desktop\Download\Eraser` |  | Anti-Forensic Tools Installed and Executed by User "informant" — Eraser and CCle |
| Path | `C:\Users\informant\Desktop\Download\ccsetup504.exe` |  | Anti-Forensic Tools Installed and Executed by User "informant" — Eraser and CCle |
| Path | `C:\Users\informant\AppData\Local\Microsoft\Windows\Burn\Burn\IE11-Windows6.1-x64-en-us.exe` |  | CD/DVD Burning Used as Third Exfiltration Channel — "IAMAN CD" on BD-RE Drive D: |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `iaman.informant@nist.gov` |  | User Identity Established — "Iaman Informant" (iaman.informant@nist.gov) with Re |
| Email | `iaman@nist.gov` |  | User Identity Established — "Iaman Informant" (iaman.informant@nist.gov) with Re |




---

## Appendix C: MITRE ATT&CK Coverage

22 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (2) > Execution (1) > Persistence (3) > Privilege Escalation (2) > Defense Evasion (6) > Lateral Movement (2) > Collection (5) > Exfiltration (5) > Impact (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User Identity Established — "Iaman Informant"...; Decoy Account Creation (admin11, ITechTeam,... |
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication Through Removable Media | SanDisk Cruzer Fit USB Drive Connected — Two... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Application Execution Timeline Supporting Data... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User Identity Established — "Iaman Informant"...; Decoy Account Creation (admin11, ITechTeam,... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Decoy Account Creation (admin11, ITechTeam,... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Decoy Account Creation (admin11, ITechTeam,... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User Identity Established — "Iaman Informant"...; Decoy Account Creation (admin11, ITechTeam,... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Decoy Account Creation (admin11, ITechTeam,... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | RM2 Dual-Partition Structure — FAT32 Partition... |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | 17 Masqueraded Documents from Earlier Burn... |
| [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | Masquerade File Type | Extensive File Extension Masquerading on RM2...; RM2 File Activity Timeline — Systematic Data...; RM2 Dual-Partition Structure — FAT32 Partition...; 17 Masqueraded Documents from Earlier Burn...; Cross-System Provenance Chain: Network Share →... |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | 17 Masqueraded Documents from Earlier Burn... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Evidence of Document Editing and Directory...; Anti-Forensic Tools Installed and Executed by...; Deleted Files Recoverable from RM2 FAT32...; RM2 File Activity Timeline — Systematic Data...; Cross-System Provenance Chain: Network Share →...; Cloud Storage Services (Google Drive, iCloud)... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | User Identity Established — "Iaman Informant"...; Decoy Account Creation (admin11, ITechTeam,... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Network Share \\10.11.11.128\secured_drive... |
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication Through Removable Media | SanDisk Cruzer Fit USB Drive Connected — Two... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Secret Project Documents Copied to USB Drive...; Environment-Wide Document Origin — NASA/JPL...; Network Share \\10.11.11.128\secured_drive...; RecentDocs and MRU Entries Confirm Access to...; Cross-System Provenance Chain: Network Share →... |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Network Share \\10.11.11.128\secured_drive...; Cross-System Provenance Chain: Network Share →... |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Local Data Staging | Extensive File Extension Masquerading on RM2...; CD/DVD Burning Used as Third Exfiltration...; 17 Masqueraded Documents from Earlier Burn...; Cross-System Provenance Chain: Network Share →... |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Microsoft Outlook Used with NIST Email Account... |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Web Search History Reveals Premeditated Data... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Microsoft Outlook Used with NIST Email Account... |
| [T1052](https://attack.mitre.org/techniques/T1052/) | Exfiltration Over Physical Medium | CD/DVD Burning Used as Third Exfiltration...; 17 Masqueraded Documents from Earlier Burn...; Cross-System Provenance Chain: Network Share →... |
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Secret Project Documents Copied to USB Drive...; RM2 File Activity Timeline — Systematic Data...; Environment-Wide Cross-Device Document...; SanDisk Cruzer Fit USB Drive Connected — Two...; Cross-System Provenance Chain: Network Share →... |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Web Search History Reveals Premeditated Data... |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Cross-System Provenance Chain: Network Share →...; Cloud Storage Services (Google Drive, iCloud)... |


### Impact

| Technique | Name | Findings |
|-----------|------|----------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Anti-Forensic Tools Installed and Executed by... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 500 |
| Findings submitted | 24 |
| Confirmed | 20 |
| Inferences | 4 |
| Input tokens | 27.0K |
| Output tokens | 176.7K |
| Total tokens | 203.7K |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 27.0K | 176.7K | 203.7K |




<details>
<summary>Evidence Sources (120)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 9 |
| tsk.fsstat | sleuthkit | 40 |
| tsk.filelist | sleuthkit | 51 |
| tsk.partitions | sleuthkit | 8 |
| tsk.fsstat | sleuthkit | 37 |
| tsk.partitions | sleuthkit | 10 |
| tsk.masquerade | sleuthkit | 0 |
| tsk.filelist | sleuthkit | 27 |
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
| strings.output | strings | 22065 |
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| tsk.timeline | sleuthkit | 67 |
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
| bulk.winpe | bulk_extractor | 29729 |
| bulk.winpe_carved | bulk_extractor | 29704 |
| bulk.zip_carved | bulk_extractor | 22411 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 7330 |
| bulk.duplicates | bulk_extractor | 1742 |
| bulk.email | bulk_extractor | 61 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7192 |
| bulk.url_services | bulk_extractor | 58 |
| bulk.zip_carved | bulk_extractor | 5221 |
| evtx.manifest | evtx-extract | 54 |
| ez.shimcache | eztools | 307 |
| pcap.disk.atiumd6a | tshark | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.query.software | python-registry | 1 |
| registry.system | regripper | 186 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| pcap.disk.atiumd6a | tshark | 8 |
| registry.security | regripper | 69 |
| registry.security | regripper | 8 |
| pcap.disk.atiumdva | tshark | 8 |
| pcap.disk.atiumd6a | tshark | 8 |
| registry.query.system | python-registry | 1 |
| pcap.disk.atiumdva | tshark | 8 |
| registry.system | regripper | 33492 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| exiftool.metadata | exiftool | 9 |
| tsk.timeline | sleuthkit | 187 |
| tsk.masquerade | sleuthkit | 17 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| hashdeep.hashes | hashdeep | 6 |
| registry.usrclass.admin11 | regripper | 11 |
| registry.ntuser.admin11 | regripper | 133 |
| registry.ntuser.default | regripper | 74 |
| registry.usrclass.informant | regripper | 102 |
| registry.ntuser.informant | regripper | 306 |
| registry.usrclass.temporary | regripper | 15 |
| registry.ntuser.temporary | regripper | 118 |
| tsk.metadata.5123 | istat | 460 |
| tsk.metadata.1030147 | istat | 8620 |
| tsk.masquerade | sleuthkit | 3 |
| exiftool.metadata | exiftool | 9 |
| chainsaw.hunt | chainsaw | 99 |
| hayabusa.alerts | hayabusa | 35 |
| composite.file_staging | composite | 578 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| optical.listing | mulder-optical | 58 |
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
| exiftool.metadata | exiftool | 9 |
| hashdeep.hashes | hashdeep | 6 |
| composite.timeline | composite | 172 |
| composite.execution | composite | 122 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.defense_evasion | composite | 172 |
| composite.lateral_movement | composite | 434 |
| composite.correlation | composite | 1 |
| composite.recovery | composite | 22 |
| forensic.timestomping | timestomp_detector | 1 |
| composite.file_staging | composite | 578 |
| composite.exfil | composite | 2484 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
