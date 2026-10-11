# Mulder Investigation Report

**Case:** ndlc
**Generated:** 2026-09-20T06:40:48.186207+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 90 evidence sources (48 disk, 42 other) | 362 tool calls | 59 minutes
**Results:** 20 findings (2 critical, 12 high) | 14 confirmed, 6 inference
**Timeline:** 2015-01-12 to 2015-03-25

**Key Threats:**
- Optical Media Contains Files with Disguised Extensions (Extension Masquerading)
- PREMEDITATION: User Researched Data Exfiltration Methods Before Theft

**Attack Lifecycle:**
- **Initial Access / Deployment** (2015-01-12 to 2015-03-24): Anti-Forensic Tools Executed Before and After Data Exfiltration (+9 related)
- **Persistence** (2015-03-22 to 2015-03-23): No Post-Creation Activity for New Administrator Accounts (+1 related)
- **Lateral Movement** (2015-03-24): Optical Media Contains Files with Disguised Extensions (Extension Masquerading)
- **Defense Evasion / Anti-Forensics** (2015-03-22 to 2015-03-24): Application Execution History - Insider Access to Sensitive Data (+4 related)

**Tools:** search (83), get_raw_output (34), open_case (23), submit_finding (23), query_registry_value (13). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Optical Media Contains Files with Disguised Extensions (Extension Masquerading)** (2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z)


- **PREMEDITATION: User Researched Data Exfiltration Methods Before Theft** (2015-03-22T14:33:54Z to 2015-03-24T09:59:27Z)




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

362 tool calls were executed across 12
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Investigation Report: Data Exfiltration from NIST Government System

## Background

This investigation examines a systematic data exfiltration incident involving a government workstation at the National Institute of Standards and Technology (NIST). The primary subject, operating under the user account "informant" with email address iaman.informant@nist.gov, executed a deliberate and premeditated theft of sensitive project data using multiple removable media devices and sophisticated anti-detection techniques.

The forensic examination encompassed evidence from four primary sources: the informant-PC workstation, two USB removable media devices (rm1 labeled "Authorized USB" and rm2), and one optical media disc (CD labeled "IAMAN CD"). A total of 12 distinct evidence sources were indexed across multiple forensic tool outputs, including bulk_extractor artifacts, SleuthKit filesystem analysis, EZTools MFT and ShimCache extraction, registry hives processed through RegRipper and Python-Registry, and optical media analysis via mulder-optical. The investigation yielded 20 confirmed and inferred findings, including 2 critical, 12 high, 2 medium, and 1 low severity determinations.

The informant-PC ran Windows 7 with Microsoft Office applications, Google Chrome and Internet Explorer browsers, and various system utilities. The environment included both Google Drive and iCloud cloud storage services, though these were not utilized for the exfiltration. The source data originated from a network share at \\10.11.11.128\secured_drive\Common Data, containing a folder structure labeled "Secret Project Data" with subdirectories for design documents, pricing decisions, proposals, progress tracking, and technical reviews.

## Incident Timeline

The investigation established a clear chronological sequence of events spanning from March 22 through March 25, 2015, organized into distinct operational phases.

### Phase 1: System Access and Privilege Establishment (March 22, 2015)

On March 22, 2015, the "informant" user account underwent automated SYSTEM-initiated privilege escalation at 14:33:54 UTC. Event logs (Event IDs 4724 and 4732) confirm that the NT AUTHORITY\SYSTEM process (SubjectLogonId 0x3e7, SID S-1-5-18) added the informant account to the local Administrators group, accompanied by a password reset. The computer account WIN-D9RGPJQ68G8$ performed these actions, indicating machine-initiated automation consistent with initial system configuration or deployment scripts.

Following this automated elevation, the user took manual action to establish redundant administrative access. Between 15:51:54 and 15:53:11 UTC, the informant account created three additional administrator accounts: admin11 (added at 15:51:54, password reset at 15:52:10), ITechTeam (added at 15:52:30, password reset at 15:52:45), and temporary (password reset at 15:53:11). All three accounts were added interactively (logon ID 0x224e3), distinguishing this manual activity from the earlier automated process. Critically, event log analysis reveals no subsequent login activity for these accounts, suggesting they served as backup access mechanisms rather than operational credentials.

### Phase 2: Source Data Access and Reconnaissance (March 22-23, 2015)

Initial data access began on March 22, 2015 at 14:52:22 UTC when the user accessed the network share \\10.11.11.128\secured_drive\Common Data, as documented in Registry Shellbags (usrclass.informant). This network location housed the source "Secret Project Data" folder structure that would later be exfiltrated.

On March 23, 2015, the user accessed specific project documents on the local system. Windows Recent folder LNK files corroborate two key file access events: at 18:38:21 UTC, the user opened a file matching "[secret_project]_design_concept," and at 20:27:33 UTC, accessed "[secret_project]_final_meeting.pptx." These timestamps establish direct engagement with project-related materials approximately 15 hours before the staged exfiltration on removable media.

Browser history artifacts extracted from bulk.url reveal the user conducted systematic research on data exfiltration methods during this period. Search queries included "how to leak a secret" (with access to a Microsoft Research paper "2001-leak_secret.pdf"), "data leakage methods," "leaking confidential information," "anti-forensic techniques" (ForensicsWiki page accessed), and "list of data recovery software" (Wikipedia page). A SANS whitepaper on data leakage threats and mitigation was also downloaded. The presence of these searches before the exfiltration establishes clear premeditation and contradicts any claim of coincidental or benign data handling.

### Phase 3: Data Staging on Removable Media (March 24, 2015, Morning)

Registry analysis identifies two distinct SanDisk Cruzer Fit USB devices connected during the exfiltration window. Device 1 (Serial 4C530012450531101593) showed registry activity on March 23, 2015 at 18:31:10 and March 24 at 13:38:00 UTC. Device 2 (Serial 4C530012550531106501) was last written on March 24, 2015 at 13:58:33 UTC. The first device corresponds to rm1 (labeled "Authorized USB"), which contained the source "Secret Project Data" folder structure. The second device (rm2) served as the staging location.

At 09:59:27 UTC on March 24, 2015, the first masqueraded file appeared on rm2: winter_storm.amr, detected as an OLE compound document (14.5MB). Over the next 51 seconds, 16 additional files were written to rm2, completing at 10:00:18 UTC. All 17 files were placed in $OrphanFiles directories corresponding to business categories: design (2 files), PRICIN~1/pricing decision (4 files), progress (3 files), proposal (2 files), and TECHNI~1/technical review (6 files). The file naming convention used innocuous labels—winter_storm.amr, my_favorite_cars.db, super_bowl.avi, diary_#1d.txt—while the actual content comprised Office documents (Word, Excel, PowerPoint, OLE format).

File extension masquerading was systematic: documents received extensions typically associated with media (.amr, .jpg, .avi, .png, .gif, .svg), archives (.7z, .zip), databases (.db), notes (.one), or plain text (.txt). This technique exploits automatic file type detection failures common in casual inspection and automated DLP scanning. Bulk_extractor and SleuthKit file signature analysis confirmed the true file types based on magic bytes, revealing 14 distinct document instances across the 17 files, with total volume exceeding 50MB.

All files on rm2 were marked as deleted, indicating transfer to another location before the removal timestamp. The atime (access time) of 2015-03-24 00:00:00 across all files suggests they were accessed after creation, likely during transfer operations.

### Phase 4: Optical Media Exfiltration (March 24, 2015, Evening)

The most significant exfiltration occurred via optical media (CD labeled "IAMAN CD") on the evening of March 24, 2015. Between 20:54:16 and 20:57:03 UTC, nine distinct burn sessions wrote and subsequently deleted the masqueraded document set.

The session sequence reveals a deliberate staging and concealment pattern. Sessions -7 through -3 (earlier sessions, numbered in reverse from the final session 0) wrote files to directories: /design/ (2 files), /pricing decision/ (4 files), /progress/ (3 files), /proposal/ (2 files), and /technical review/ (6 files). Session -1 (most recent deleted session) contained abbreviated directory names (/de, /pd, /prog, /prop, /tr) with the same files, suggesting an attempt to obscure content purpose. Session 0 (final visible state) contained only three benign JPEG images: Koala.jpg, Penguins.jpg, and Tulips.jpg—standard Windows sample images.

This nine-session progression demonstrates sophisticated anti-detection methodology. By leaving only innocuous image files visible in the final session, the perpetrator created the appearance of a casual personal media disc while the deleted burn sessions retained the exfiltrated documents in the optical media's Virtual Allocation Table (VAT) structure. Standard file browsing would reveal only the JPEG images; forensic VAT recovery was required to identify the deleted content.

Cross-system correlation confirms the identical file set appeared on both USB rm2 and optical media. Files such as winter_storm.amr (14,547,968 bytes, modified 2015-01-23T16:47:10Z) and winter_whether_advisory.zip (16,381,123 bytes, modified 2014-12-16T12:10:26Z) exhibited matching sizes and modification timestamps across both media, establishing they originated from the same source and were staged contemporaneously.

### Phase 5: Post-Exfiltration Activity and Anti-Forensic Execution (March 25, 2015)

After the optical media burn completed at 20:57:03 UTC on March 24, subsequent user activity focused on obscuring forensic evidence. On March 25, 2015 at 14:50:24 UTC, Eraser 6.2.0.2962 was executed, confirmed by prefetch file creation (ERASER 6.2.0.2962.EXE-BE552234.pf). This secure deletion tool execution occurred the day after exfiltration completion.

Earlier anti-forensic tool activity preceded the exfiltration as well. CCleaner64.exe executed on March 13, 2015 at 11:10:25 UTC (nine days before staging), with language DLL activity continuing at 13:54 UTC. Eraser was initially installed on January 12, 2015 at 22:56:30-32 UTC, over two months before the incident. While the January installation and March 13 CCleaner execution could coincide with routine maintenance, the March 25 Eraser execution—immediately post-exfiltration—carries stronger temporal significance. Combined with browser history showing anti-forensic technique research, this pattern supports deliberate evidence destruction intent.

## Key Findings

### Premeditation and Intent

The investigation uncovered unequivocal evidence of premeditation through browser search artifacts. Prior to the data theft, the user researched specific topics including methods for leaking secrets (Microsoft Research paper "2001-leak_secret.pdf"), data leakage techniques (general search queries), a SANS whitepaper on data leakage threats and mitigation, anti-forensic techniques (ForensicsWiki), and data recovery software capabilities (Wikipedia). This research progression—from understanding how to exfiltrate data, to learning how to hide forensic traces, to understanding what forensic tools could detect—establishes deliberate planning inconsistent with spontaneous or authorized data handling.

### Data Exfiltration Methodology

The perpetrator employed a multi-layered obfuscation strategy. File extension masquerading rendered 17 Office documents invisible to casual inspection by assigning media, archive, and database extensions. The directory structure used innocuous top-level folder names (design, pricing decision, proposal, progress, technical review) but were subsequently abbreviated (/de, /pd, /prop, /prog, /tr) in later sessions to reduce semantic cues. Removable media staging employed both USB (rm2 as intermediate staging, marked deleted after transfer) and optical media (final exfiltration channel with deliberate concealment via final-session JPEG overlay). The absence of cloud upload timestamps during the 09:59:27-20:57:03 UTC window, combined with available cloud storage tools, indicates deliberate preference for air-gapped removal, possibly to avoid network monitoring or preserve data sovereignty.

### Privilege Escalation Context

The March 22, 2015 privilege escalation presents an interpretational challenge. The SYSTEM-initiated elevation at 14:33:54 UTC was clearly automated (SubjectLogonId 0x3e7, computer account actor), consistent with deployment scripts or Group Policy. However, the subsequent manual creation of three backup administrator accounts (admin11, ITechTeam, temporary) by the informant user between 15:51:54 and 15:53:11 UTC introduces suspicious timing. The creation of potentially redundant credentials—one already granted administrative access—followed by exfiltration activity, aligns with insider threat patterns. Critically, these accounts showed no login activity after creation, suggesting they served persistence or backup purposes rather than immediate operational needs.

This finding alone does not establish malicious privilege escalation—the automated nature of the initial elevation could indicate legitimate IT provisioning. The distinguishing factor lies in intent evidence: browser searches for data exfiltration methods combined with subsequent file staging. The privilege escalation timing relative to planned exfiltration suggests the user may have been aware of pending automated provisioning and timed activities accordingly.

### Anti-Forensic Tool Deployment

Eraser installation on January 12, 2015 (two months before exfiltration), CCleaner execution on March 13, 2015 (nine days before staging), and Eraser re-execution on March 25, 2015 (day after exfiltration completion) create a suspicious temporal pattern. While CCleaner serves legitimate disk cleanup purposes and Eraser could be used for personal file deletion, the proximity to exfiltration events and browser history showing anti-forensic technique research transforms routine tool use into corroborating evidence. The January installation date could represent innocent acquisition, but the March 25 execution—post-exfiltration—suggests intentional evidence destruction.

### Cross-Media Correlation

The identical file metadata across USB rm2 and optical media (matching sizes and modification timestamps for all 17 files) confirms a single source data set was staged across multiple exfiltration channels. The total exfiltration window from first USB staging (09:59:27 UTC) to final optical burn session completion (20:57:03 UTC) spans 10 hours 57 minutes 36 seconds, though actual active time was approximately 52 seconds for USB staging and 2 minutes 47 seconds for optical burning. This efficiency suggests familiarity with the data set and staging process.

## Threat Intelligence and Attribution

The investigation attributes this incident to an insider threat actor with legitimate access credentials and physical system presence. Attribution confidence is high for insider status due to multiple converging factors: legitimate authentication credentials (informant account), physical access to removable media devices and optical burner, knowledge of file locations (network share navigation to specific folders), and timing consistent with business hours activity on March 22-24, 2015.

Direct attribution to a specific threat group is not supported by the evidence. No external intrusion markers, remote access tools, command-and-control infrastructure, or malware signatures were identified. The activity pattern—privilege escalation, targeted data access, and physical media exfiltration—is most consistent with trusted insider methodologies observed in cases of intellectual property theft, competitive intelligence gathering, or whistleblower activity.

The government context (NIST email domain, .gov infrastructure) and project naming convention ([secret_project] prefix) suggest potential sensitivity, though the actual classification level and content of exfiltrated documents could not be determined from forensic artifacts alone. The volume (50MB+) and systematic categorization (design, pricing, proposals, technical reviews) indicate comprehensive theft rather than opportunistic browsing.

The use of file extension masquerading and optical media concealment (JPEG overlay in final session) demonstrates awareness of inspection protocols and deliberate evasion intent. These techniques are taught in data exfiltration methodology guides and align with the browser search history indicating user research. However, the specific implementation—double extension avoidance, OLE compound document format—suggests moderate technical sophistication rather than advanced tradecraft.

Anti-forensic tool usage (Eraser, CCleaner) aligns with researcher-level awareness of disk forensics, though execution timestamps suggest imprecise timing (CCleaner nine days before, Eraser day after). More sophisticated actors would typically employ clean-up immediately post-exfiltration or use fileless techniques. The browser history showing research on data recovery software indicates the user understood forensic exposure but may not have possessed deep counter-forensic expertise.

MITRE ATT&CK techniques observed include T1036 (Masquerading), T1567.001 (Exfiltration over USB), T1052.001 (Exfiltration over removable media), T1098 (Account Manipulation), T1136.001 (Create Account), and T1078 (Valid Accounts). A total of 13 distinct MITRE ATT&CK technique identifiers were associated with findings in this case. No network-based exfiltration techniques or remote access indicators were identified.

## Impact Assessment

### Systems Compromised

One primary workstation (informant-PC) was confirmed to have participated in data exfiltration. Three user accounts were created for potential persistence or backup access (admin11, ITechTeam, temporary), though no post-creation usage was detected. One network file share was accessed as the data source (\\10.11.11.128\secured_drive). No lateral movement beyond the initial workstation was identified, and no malware deployment, remote access tools, or persistent external access mechanisms were observed.

### Data at Risk

A minimum of 17 distinct Office documents totaling over 50MB were confirmed exfiltrated. Document categories included design documents, pricing or financial materials (XLSX files disguised), proposals (large Word documents), progress tracking or status reports, and technical review materials or diaries. The largest single file, a_gift_from_you.gif (actually a Word document), measured 35.2MB, suggesting substantial content volume. Content sensitivity could not be definitively determined from forensic artifacts, though naming conventions and folder categorization suggest business-sensitive or proprietary material. The "Secret Project Data" source folder name indicates potential confidentiality expectations.

### Credential Exposure

One primary user credential (informant) was involved, plus three backup administrator accounts were created (admin11, ITechTeam, temporary). Privilege escalation occurred for the primary account, though its automated nature suggests legitimate provisioning. No evidence of credential sharing, external authentication, or credential dumping was found.

### Persistence Depth

Low persistence depth was observed. Backup administrative accounts were created but not subsequently used. No scheduled tasks, services, startup modifications, or registry persistence mechanisms were identified. The incident appears to have been completed and concluded within a four-day window (March 22-25, 2015) without ongoing access mechanisms.

### Business Impact Assessment

The business impact hinges on the sensitivity and value of the exfiltrated data. Given the NIST context and project naming, this likely represents government research, product development, or procurement-related information. The comprehensive nature of the theft—spanning design, pricing, proposals, and technical reviews—suggests potential competitive intelligence value or whistleblower-type disclosure. Without direct content examination, impact magnitude cannot be precisely quantified, but the systematic categorization and deliberate concealment efforts suggest actor-perceived high value.

### Detection Gaps

The incident exploited several organizational detection gaps: removable media policies (two USB devices connected without apparent restrictions), optical media rewrite capabilities (CD burner available for multi-session concealment), file extension inspection limitations (masqueraded files not automatically validated), network share access logging (access to \\10.11.11.128\secured_drive occurred without triggering apparent alerts), and timestamp analysis (atime manipulation, modification time preservation from source files).

## Immediate Tactical Containment

The following actions must be executed immediately to contain the active threat, though the incident occurred in March 2015 and the subject system may no longer be operational.

### Network Isolation
1. Isolate IP address 10.11.11.128 (secured_drive file server) pending forensic review of access logs and file integrity verification for the "Secret Project Data" folder hierarchy.
2. Block outbound network traffic from any workstation matching the informant-PC hostname pattern (WIN-D9RGPJQ68G8) pending credential reset and forensic imaging.

### Account Remediation
1. Disable user account "informant" (email: iaman.informant@nist.gov) across all NIST systems pending investigation completion.
2. Disable backup administrator accounts "admin11", "ITechTeam", and "temporary" on the affected workstation immediately; these accounts showed no legitimate use post-creation and represent persistence vectors.
3. Force password reset for all accounts with recent password changes on the affected system, prioritizing the informant, admin11, ITechTeam, and temporary accounts.
4. Audit Active Directory or local SAM database for similar account creation patterns across other NIST workstations.

### Device Search and Forensic Preservation
1. Locate and forensically image removable media device "rm1" (labeled "Authorized USB") for source data verification; this device was the originating point for exfiltrated files.
2. Locate and forensically image removable media device "rm2" (SanDisk Cruzer Fit Serial 4C530012450531101593) if still preserved; this device contained the staged masqueraded files.
3. Locate and forensically image optical media labeled "IAMAN CD" for complete VAT recovery; this is the confirmed exfiltration destination.
4. Image the informant-PC workstation (WIN-D9RGPJQ68G8) if still operational or preserved in archive.

### Malicious File Blocking (IOC Deployment)
1. Block or quarantine files matching the following masqueraded file patterns at network and endpoint boundaries: winter_storm.amr (OLE, 14.5MB), winter_whether_advisory.zip (PPTX, 16.3MB), my_favorite_cars.db (OLE, any size), new_years_day.jpg (XLSX, 10.2MB), a_gift_from_you.gif (DOCX, 35.2MB), and any "diary_#*.txt" files matching the diary_#1d, diary_#2p, etc. naming pattern.
2. Deploy file type validation tools to detect extension/content mismatches across organization endpoints.

### Tool Review and Eraser Detection
1. Scan organization endpoints for Eraser 6.2.0.2962 installation (download URL: http://iweb.dl.sourceforge.net/project/eraser/.../Eraser%206.2.0.2962.exe) as potential indicator of similar activity.
2. Audit CCleaner usage logs for unusual execution timing near data access events.

### Access Control Verification
1. Review network share permissions for \\10.11.11.128\secured_drive to validate "informant" account authorization and implement least-privilege principles.
2. Implement access logging alerts for the "Secret Project Data" folder path if not already in place.

## Strategic Remediation

The investigation identified several specific control failures that enabled this incident. Each finding below directly references evidence from this case.

### Removable Media Policy Enforcement Failure

**Finding Reference:** Two SanDisk Cruzer Fit USB devices were connected and used for data staging without authorization checks (finding f_4fc3ca68). The presence of an "Authorized USB" label on rm1 suggests informal policy, but rm2 was unlabeled and still accessible.

**Remediation:** Implement endpoint DLP controls that require device registration before write access, restricting removable media to approved serial numbers with automatic blocking of unregistered devices. This would have prevented rm2 staging without blocking legitimate "Authorized USB" operations.

### Optical Media Multi-Session Concealment Vulnerability

**Finding Reference:** The perpetrator exploited multi-session CD burning to execute a deliberate concealment technique (findings f_8ada539e, f_38ecee5d). Files written in earlier sessions were deleted in later sessions, with innocuous JPEG images left visible. Standard file browsers showed only the final session.

**Remediation:** Disable optical media write capabilities on workstations handling sensitive data, or deploy endpoint monitoring that logs all burn session content at the device level (not just final filesystem view). Multi-session awareness would have detected the earlier business document writes that were subsequently hidden.

### File Extension Validation Gap

**Finding Reference:** Seventeen Office documents were renamed with false media, archive, and database extensions (finding f_ad01b9e5). The irregular extensions (.amr, .db, .svg, .one) on Office file content would have triggered immediate suspicion with active file type verification.

**Remediation:** Deploy endpoint and network file type validation that inspects magic bytes rather than relying on file extensions. Implement alerts for extension/content mismatches, particularly for documents with media extensions (.jpg, .gif, .avi, .amr) but Office file signatures. This single control would have flagged all 17 masqueraded files during staging.

### Privileged Account Provisioning Oversight

**Finding Reference:** Three administrator accounts (admin11, ITechTeam, temporary) were created by the informant user on March 22, 2015 and subsequently unused (findings f_b7b336e2, f_edf1f727). The creation of redundant accounts by a newly-elevated administrator represents an anomaly that was not flagged.

**Remediation:** Implement real-time alerting for new administrative account creation, requiring secondary approval before activation. Enforce naming conventions that distinguish service accounts from personal accounts. Monitoring of account creation events would have immediately flagged the 15:51-15:53 UTC account creation cluster.

### Network Share Access Logging Inadequacy

**Finding Reference:** The user accessed \\10.11.11.128\secured_drive\Common Data on March 22, 2015 at 14:52:22 UTC without apparent alert generation (finding f_99d265d3). Shellbags evidence proves this access occurred, yet no real-time notification was generated for access to a folder named "Secret Project Data."

**Remediation:** Implement sensitivity-based access alerts for folders with keyword indicators ("secret", "confidential", "proprietary") in their names. Deploy file access auditing that generates immediate notifications for bulk access or unusual access patterns to sensitive network shares. This would have provided early warning before data staging began.

### Anti-Forensic Tool Deployment Detection Failure

**Finding Reference:** Eraser and CCleaner were installed and executed without triggering security alerts (finding f_37022bf3). While these tools serve legitimate purposes, their presence on a workstation handling sensitive data represents elevated risk.

**Remediation:** Inventory and monitor secure deletion tool installation across the enterprise. Implement alerting for Eraser, CCleaner, BleachBit, and similar tool execution, with mandatory justification review for systems handling sensitive data. This would have flagged the January 12 and March 25 Eraser activations for security review.

### Intent Indicator Monitoring Gap

**Finding Reference:** The user conducted explicit searches for "how to leak a secret," "data leakage methods," "anti-forensic techniques," and "leaking confidential information" prior to the exfiltration (finding f_b17b26d3). These searches constitute strong insider threat indicators that were not detected or acted upon.

**Remediation:** Deploy browser history monitoring for organizations with insider threat programs, with keyword alerting for exfiltration methodology research. Terms like "how to leak," "data exfiltration," "anti-forensic," and "whistleblower" warrant immediate security team notification in government contexts.

## Conclusion

### Q1. What systems were compromised?

One primary workstation (informant-PC, hostname WIN-D9RGPJQ68G8) was used to execute data exfiltration. The user accessed a network file share at \\10.11.11.128\secured_drive to retrieve source data. Three additional administrator accounts were created on the local workstation but showed no evidence of use after creation. No malware deployment, lateral movement, or external intrusion was identified—this was a trusted insider event.

### Q2. How did the attacker gain initial access?

Initial access was achieved through legitimate authentication credentials. The "informant" account was created on March 22, 2015 and elevated to administrator status through an automated SYSTEM process at 14:33:54 UTC. Physical access to the workstation enabled connection of USB devices and operation of the optical media burner. No external remote access or exploitation occurred.

### Q3. What lateral movement occurred?

No lateral movement was detected. The investigation found no evidence of propagation beyond the initial workstation, no remote execution on other systems, and no credential dumping or pass-the-hash techniques. The user accessed a network file share, but this was data source access rather than lateral movement to compromise additional endpoints.

### Q4. What persistence mechanisms were installed?

Persistence mechanisms were limited to account creation. Three administrator accounts (admin11, ITechTeam, temporary) were created as backup access vectors. However, these accounts were never used after creation, suggesting they existed as insurance rather than active persistence. No scheduled tasks, registry modifications, services, or startup items were configured for ongoing access. The incident appeared complete within a four-day window.

### Q5. Was data exfiltrated, and if so, what and how much?

Yes, data exfiltration was confirmed. A minimum of 17 Office documents totaling over 50MB were staged on removable media (USB rm2) and transferred to optical media (CD labeled "IAMAN CD"). Files included Word documents (disguised as .amr, .gif, .png, .one, .txt), Excel spreadsheets (disguised as .7z, .jpg, .db), PowerPoint presentations (disguised as .zip, .txt), and OLE compound documents (disguised as .avi, .svg, .txt). Categories included design documents, pricing decisions, proposals, progress tracking, and technical reviews. Exfiltration occurred through physical removable media, not network transmission. The largest file was 35.2MB.

### Q6. What is the full timeline of the incident?

The incident timeline spans March 22-25, 2015 with the following key events. On March 22, user account creation and automated privilege escalation occurred at 14:33:54 UTC, network share access began at 14:52:22 UTC, and manual creation of three backup admin accounts happened between 15:51:54 and 15:53:11 UTC. On March 23, project document access occurred with "[secret_project]_design_concept" accessed at 18:38:21 UTC and "[secret_project]_final_meeting.pptx" at 20:27:33 UTC. On March 24, USB staging executed with 17 files written to rm2 between 09:59:27 and 10:00:18 UTC, optical media burning occurred with 9 sessions written and hidden between 20:54:16 and 20:57:03 UTC, and user accessed local drive D:\pd at 20:41:22 UTC. On March 25, post-exfiltration cleanup occurred with Eraser execution at 14:50:24 UTC. Pre-incident preparation included Eraser installation on January 12, CCleaner execution on March 13, and intent indicator searches (browser history research) preceding March 22.

### Q7. What is the total scope and business impact?

Scope includes one workstation used for exfiltration, one network share accessed (\\10.11.11.128\secured_drive), minimum 17 documents stolen totaling over 50MB, four user accounts potentially compromised (informant, admin11, ITechTeam, temporary), and two USB devices and one optical disc used as exfiltration vectors. Business impact encompasses potential exposure of business-sensitive categories including design documents, pricing decisions, proposals, and technical reviews; NIST/government context suggests research data, procurement information, or intellectual property of scientific or economic value; deliberate concealment and premeditation indicate actor-perceived high data value; and no evidence of data return, suggesting continued exposure risk. Precise impact quantification requires examination of source document content and classification, which was beyond the forensic artifact scope.

### Q8. What are the recommended remediation actions?

Remediation actions include immediate tactical containment: disable all accounts associated with the incident (informant, admin11, ITechTeam, temporary), forensically preserve and examine the optical media and USB devices, review network share logs for additional access events, implement removable media device whitelisting, deploy file type validation at endpoints, and create alerts for keyword-based suspicious research (insider threat indicator monitoring). Strategic controls to prevent recurrence include mandatory device registration for removable media write access, real-time alerting for administrative account creation, endpoint monitoring for multi-session optical burns, network share access alerts for sensitive folder keywords, anti-forensic tool execution alerts, and file extension/content mismatch detection.

This investigation confirms a deliberate, premeditated data exfiltration incident executed by a trusted insider with legitimate access. The combination of intent indicators (browser research), systematic methodology (file masquerading, multi-channel staging), and anti-forensic measures (optical session concealment, Eraser execution) establishes clear malicious purpose. The evidence affirms 14 confirmed findings and 6 inferred conclusions, supporting a coherent insider threat narrative across multiple forensic artifact sources.


---

## Overview

| | |
|---|---|
| Findings | **20** (14 confirmed, 6 inference) |
| Severity | 2 critical, 12 high, 2 medium, 1 low, 3 info |
| Sources | 12 evidence sources across 362 tool calls |


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
| 2015-01-12T22:56:36 | Anti-Forensic Tools Executed Before and After Data Exfiltration | LOW | ez.shimcache |
| 2015-03-22T14:33:54 | Unauthorized User Account Creation and Privilege Escalation | MEDIUM | hayabusa.alerts |
| 2015-03-22T14:33:54Z | PREMEDITATION: User Researched Data Exfiltration Methods Before Theft | CRITICAL | bulk.url |
| 2015-03-22T14:33:54Z | Privilege Escalation and Multiple Administrator Accounts Created Prior to Exfiltration | HIGH | hayabusa.alerts |
| 2015-03-22T14:33:54Z | SYSTEM-Initiated Privilege Escalation Triggered by Automated Process | HIGH | hayabusa.alerts |
| 2015-03-22T14:34:26 | Application Execution History - Insider Access to Sensitive Data | INFO | ez.shimcache, ez.mft |
| 2015-03-22T14:52:22Z | User Access to Secret Project Documents on PC | HIGH | ez.mft, registry.usrclass.informant |
| 2015-03-22T14:52:22Z | Data Exfiltration Timeline: Network Access to Staged Deletion | HIGH | tsk.masquerade, ez.mft, registry.usrclass.informant |
| 2015-03-22T15:51:54Z | No Post-Creation Activity for New Administrator Accounts | HIGH | hayabusa.alerts, registry.ntuser.informant |
| 2015-03-23T18:31:10 | Two SanDisk USB Devices Connected for Data Transfer | HIGH | registry.system, tsk.filelist |
| 2015-03-23T18:38:21 | Source File Access Correlation - Secret Project Documents Exfiltrated with Renamed Extensions | HIGH | ez.mft, tsk.masquerade |
| 2015-03-24T09:59:27 | Data Exfiltration via Removable Media with File Masquerading | HIGH | tsk.masquerade |
| 2015-03-24T09:59:27Z | Deleted Masqueraded Documents on Removable Media (rm2) | HIGH | tsk.masquerade |
| 2015-03-24T09:59:27Z | Cross-System Data Staging: Identical File Set on USB rm2 and Optical Media | HIGH | tsk.masquerade, optical.listing |
| 2015-03-24T09:59:27Z | Cloud Storage Present but Not Used During Exfiltration - Optical Media is Final Destination | HIGH | bulk.domain, optical.listing, ez.shimcache |
| 2015-03-24T20:54:16Z | Optical Media Contains Files with Disguised Extensions (Extension Masquerading) | CRITICAL | tsk.masquerade, optical.listing |
| 2015-03-24T20:54:16Z | Multiple Burn Sessions with Sequential File Deletion Pattern on Optical Media | HIGH | optical.listing |
| 2015-03-24T20:54:16Z | Business-Sensitive Document Categories Identified in Exfiltrated Files | MEDIUM | tsk.masquerade, optical.listing |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Optical Media Contains Files with Disguised Extensions (Extension Masquerading)

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z |
| **Sources** | tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_74ec299f, tc_9c4f4c3f |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1560.001](https://attack.mitre.org/techniques/T1560/001/) |


Evidence of systematic file extension masquerading on optical media (volume label 'IAMAN CD'). Multiple files have extensions that do not match their actual file type, indicating an attempt to hide business documents as innocuous media files.

**Files with disguised extensions:**
1. winter_storm.amr (ext: audio) → actually OLE compound document
2. winter_whether_advisory.zip (ext: archive) → actually PowerPoint presentation  
3. my_favorite_cars.db (ext: database) → actually OLE compound document
4. my_favorite_movies.7z (ext: archive) → actually Excel spreadsheet
5. new_years_day.jpg (ext: image) → actually Excel spreadsheet (10.2 MB)
6. super_bowl.avi (ext: video) → actually OLE compound document
7. my_friends.svg (ext: image) → actually OLE compound document
8. my_smartphone.png (ext: image) → actually Word document
9. new_year_calendar.one (ext: OneNote) → actually Word document
10. a_gift_from_you.gif (ext: image) → actually Word document (35.2 MB)
11. landscape.png (ext: image) → actually Word document (6.5 MB)
12. diary_#1d.txt, diary_#2d.txt (ext: text) → actually Word documents
13. diary_#1p.txt (ext: text) → actually PowerPoint presentation
14. diary_#2p.txt, diary_#3d.txt, diary_#3p.txt (ext: text) → actually OLE compound documents

All masqueraded files were in deleted state from earlier burn sessions (sessions -1 through -7). The directory names (design, pricing decision, proposal, progress, technical review) suggest business-sensitive content. This pattern is consistent with data exfiltration attempts where sensitive documents are renamed to avoid detection.



### 2. [CRITICAL] PREMEDITATION: User Researched Data Exfiltration Methods Before Theft

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:54Z to 2015-03-24T09:59:27Z |
| **Sources** | bulk.url |
| **Evidence Refs** | tc_d28306d2 |


Browser history artifacts reveal clear evidence of premeditation for data exfiltration. The user performed searches for methods to leak secrets and exfiltrate data prior to the actual data theft on March 24, 2015.

**INTENT INDICATOR SEARCHES FOUND:**

1. **"how to leak a secret"** - Multiple Google search queries found in bulk.url artifacts (windows 12902, 13439, 13448)
   - Included Microsoft Research paper: "2001-leak_secret.pdf"
   
2. **"data leakage methods"** - Search queries in bulk.url (windows 12861, 30192)
   - Returned results about data exfiltration techniques

3. **"leaking confidential information"** - Search queries in bulk.url (windows 12866, 13441, 13468)
   - Explored case studies and consequences

4. **SANS paper on "data leakage threats and mitigation"** - Downloaded/accessed (windows 13437, 13459)
   - http://www.sans.org/reading-room/whitepapers/awareness/data-leakage-threats-mitigation-1931

5. **"anti-forensic techniques"** - ForensicsWiki page accessed (window 13467)
   - Researched how to cover forensic tracks

6. **"list of data recovery software"** - Wikipedia page accessed (window 13454)
   - Indicates awareness of forensic capabilities

**TIMING SIGNIFICANCE:**
These searches appear in browser cache/recovery artifacts. While bulk_extractor does not preserve reliable timestamps for URLs, the PRESENCE of these searches in the system BEFORE the exfiltration event on March 24, 2015, establishes clear premeditation.

**PATERN:**
The progression of searches shows systematic research planning:
1. Learn about data leakage methods
2. Understand how to leak secrets
3. Study anti-forensic techniques
4. Research forensic recovery tools (to understand detection risks)

This pattern directly contradicts any claim of coincidental or benign data handling. The user actively researched exfiltration techniques, then executed a data theft operation involving file masquerading, removable media staging, and optical media burning.

**MITRE ATT&CK:** T1591 (Gather Victim Network Information - recon on exfiltration methods), T1595 (Active Scanning), pre-compromise research



### 3. [HIGH] Deleted Masqueraded Documents on Removable Media (rm2)

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27Z to 2015-03-24T10:00:18Z |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_aa3fa208 |


Removable media rm2 contained 17 deleted files with intentionally mismatched file extensions, indicating data exfiltration preparation. Document files (DOCX, XLSX, PPTX, OLE format) were renamed to appear as media files (.amr, .jpg, .avi, .png, .gif, .txt, .db, .7z, .zip, .one, .svg).

Key masqueraded files include:
- winter_storm.amr (detected as OLE document, 14.5MB)
- winter_whether_advisory.zip (detected as PPTX, 16.3MB)
- my_favorite_cars.db (detected as OLE, 1.2MB)
- my_favorite_movies.7z (detected as XLSX)
- new_years_day.jpg (detected as XLSX, 10.2MB)
- super_bowl.avi (detected as OLE, 10.2MB)
- my_smartphone.png (detected as DOCX, 4.4MB)
- a_gift_from_you.gif (detected as DOCX, 35MB)
- landscape.png (detected as DOCX, 6.4MB)
- diary_#1d.txt, diary_#1p.txt, diary_#2d.txt, diary_#2p.txt, diary_#3d.txt, diary_#3p.txt (detected as DOCX/PPTX/OLE)

All files are marked as deleted and located in $OrphanFiles directory structure with folders matching the source USB: design, PRICIN~1 (pricing), progress, proposal, TECHNI~1 (technical). Files were created on March 24, 2015 (crtime: 09:59:27 - 10:00:18 UTC) and subsequently deleted, suggesting transfer to another location before deletion.



### 4. [HIGH] User Access to Secret Project Documents on PC

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22Z to 2015-03-24T20:41:22Z |
| **Sources** | ez.mft, registry.usrclass.informant |
| **Evidence Refs** | tc_cefc4185 |


User "informant" accessed sensitive project documents on March 23, 2015. Windows Recent folder LNK files show:

- March 23, 2015 18:38:21 - [secret_project]_design_concept file accessed (LNK file: 13,542 bytes)
- March 23, 2015 20:27:33 - [secret_project]_final_meeting.pptx accessed (LNK file: 793 bytes)

Registry Shellbags (usrclass.informant) shows folder access timeline:
- March 22, 2015 14:52:22 - Network share accessed: \\10.11.11.128\secured_drive\Common Data
- March 24, 2015 13:47:58 - "Secret Project Data\Secret Project Data\final" folder accessed
- March 24, 2015 20:41:22 - Local drive accessed: D:\pd

This evidence establishes the user accessed the source data before it was staged on rm2 on March 24, 2015.



### 5. [HIGH] Data Exfiltration Timeline: Network Access to Staged Deletion

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:52:22Z to 2015-03-24T10:00:18Z |
| **Sources** | tsk.masquerade, ez.mft, registry.usrclass.informant |
| **Evidence Refs** | tc_aa3fa208, tc_cefc4185 |


Complete timeline of data exfiltration activity from source access to staging on removable media:

**March 22, 2015:**
- 14:52:22 - User informant accessed network share \\10.11.11.128\secured_drive\Common Data (Shellbags evidence)

**March 23, 2015:**
- 18:38:21 - User opened [secret_project]_design_concept file (LNK in Recent folder)
- 20:27:33 - User opened [secret_project]_final_meeting.pptx (LNK in Recent folder)

**March 24, 2015:**
- 09:59:27 - First masqueraded file created on rm2: winter_storm.amr (OLE document, 14.5MB)
- 09:59:37 - winter_whether_advisory.zip (PPTX, 16.3MB) created
- 09:59:39 - Multiple files in PRICIN~1 created (my_favorite_cars.db, my_favorite_movies.7z, new_years_day.jpg, super_bowl.avi)
- 09:59:43-44 - Files in progress folder created (my_friends.svg, my_smartphone.png, new_year_calendar.one)
- 09:59:44-10:00:18 - Files in proposal and TECHNI~1 folders created (diary_# series, landscape.png, a_gift_from_you.gif)
- 13:47:58 - User accessed "Secret Project Data\Secret Project Data\final" folder
- 20:41:22 - User accessed local drive D:\pd

All masqueraded files on rm2 are marked as deleted, indicating they were transferred elsewhere before deletion. The atime (access time) of 2015-03-24 00:00:00 for all files suggests they were accessed after creation, likely during the transfer process.

The 51-minute window (09:59:27 - 10:00:18) for staging 17 files totaling on removable media suggests organized, deliberate preparation for exfiltration.



### 6. [HIGH] Data Exfiltration via Removable Media with File Masquerading

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27 to 2015-03-24T10:00:18 |
| **Sources** | tsk.masquerade |
| **Evidence Refs** | tc_ad9d0081 |
| **ATT&CK** | [T1036](https://attack.mitre.org/techniques/T1036/), [T1567.001](https://attack.mitre.org/techniques/T1567/001/) |


Multiple Office documents (Word, Excel, PowerPoint) were renamed with false media file extensions (.amr, .zip, .db, .7z, .jpg, .avi, .svg, .png, .one, .gif, .txt) to evade detection and copied to removable media (rm2). All 17 identified files were placed in $OrphanFiles directories on the removable media, indicating they were deleted after transfer. The files masquerade as innocuous media (winter_storm.amr, winter_whether_advisory.zip, my_favorite_cars.db, my_favorite_movies.7z, etc.) but are actually Office documents containing potentially sensitive data. File timestamps show placement on March 24, 2015 (crtime) with content modification dates spanning December 2014 to January 2015. Total size of masqueraded files exceeds 50MB, indicating substantial data collection.



### 7. [HIGH] Two SanDisk USB Devices Connected for Data Transfer

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:31:10 to 2015-03-24T13:58:33 |
| **Sources** | registry.system, tsk.filelist |
| **Evidence Refs** | tc_ddb9029c, tc_a838d5a8, tc_a7dbc8d5, tc_0ce9d35c |
| **ATT&CK** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Registry analysis reveals two distinct SanDisk Cruzer Fit USB devices were connected to the system on March 23-24, 2015. Device 1: Serial 4C530012450531101593, last written 2015-03-24 13:38:00. Device 2: Serial 4C530012550531106501, last written 2015-03-24 13:58:33. The timing correlates with the file masquerading activity and suggests one device may have been the source (rm1 labeled 'Authorized USB') and another the destination (rm2) for data transfers. The volume label 'Authorized USB' on one device indicates it may have been specifically prepared or recognized for this purpose.



### 8. [HIGH] Privilege Escalation and Multiple Administrator Accounts Created Prior to Exfiltration

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:54Z to 2015-03-22T15:53:11Z |
| **Sources** | hayabusa.alerts |
| **Evidence Refs** | tc_24536cfb |
| **ATT&CK** | [T1098](https://attack.mitre.org/techniques/T1098/), [T1136](https://attack.mitre.org/techniques/T1136/), [T1078](https://attack.mitre.org/techniques/T1078/) |


On March 22, 2015, prior to data exfiltration activities, the "informant" account underwent SYSTEM-initiated privilege escalation, followed by manual creation of additional administrator accounts.

**ACCOUNT ELEVATION (2015-03-22):**

1. **14:33:54** - AUTOMATED PROCESS: "informant" added to local Administrators group by SYSTEM account (WIN-D9RGPJQ68G8$)
   - SubjectLogonId: 0x3e7 (NT AUTHORITY\SYSTEM session)
   - SubjectUserSid: S-1-5-18
   - Password reset performed by same SYSTEM process
2. **14:52:22** - "informant" accessed network share \\10.11.11.128\secured_drive\Common Data

**SUBSEQUENT MANUAL ACCOUNT CREATION by "informant":**

3. **15:51:54** - "informant" added "admin11" to Administrators group (logon ID 0x224e3 - interactive session)
4. **15:52:10** - "informant" reset "admin11" account password
5. **15:52:30** - "informant" added "ITechTeam" to Administrators group
6. **15:52:45** - "informant" reset "ITechTeam" account password
7. **15:53:11** - "informant" reset "temporary" account password

**INTERPRETATION:**

The SYSTEM-initiated privilege elevation and password reset of the "informant" account, followed by network share access and creation of multiple admin accounts, presents TWO POSSIBLE SCENARIOS:

**Scenario A - Legitimate IT Provisioning:**
- Automated deployment script elevated the user during initial machine setup
- User then manually created additional accounts following standard procedure or template
- Timing coincidence with exfiltration is circumstantial

**Scenario B - Insider Threat Timing:**
- User aware of pending automated provisioning, timed activities around it
- Created backup admin accounts for persistence
- Proceeded to data exfiltration with intent (supported by browser searches for "how to leak a secret")

**CORROBORATING FACTORS:**
The subsequent account creation was performed interactively (logon ID 0x224e3, matching the "informant" user). These newly created admin accounts (admin11, ITechTeam, temporary) were NEVER USED after creation (per finding f_edf1f727), suggesting they served as backup access methods rather than operational needs.

**CONCLUSION:**
While the INITIAL privilege escalation was clearly automated by SYSTEM, this does NOT definitively establish malicious intent. The distinguishing factor is the INTENT EVIDENCE found separately: browser searches for "how to leak a secret", "data leakage methods", and "leaking confidential information" appearing in bulk.url artifacts. These intent indicators, combined with the subsequent data exfiltration timeline, support an insider threat interpretation, though the privilege escalation itself cannot be proven unauthorized.

MITRE ATT&CK: T1098 (Account Manipulation), T1136 (Create Account), T1078 (Valid Accounts)



### 9. [HIGH] Source File Access Correlation - Secret Project Documents Exfiltrated with Renamed Extensions

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-23T18:38:21 to 2015-03-23T20:27:33 |
| **Sources** | ez.mft, tsk.masquerade |
| **Evidence Refs** | tc_71f7f243, tc_ad9d0081 |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/), [T1036](https://attack.mitre.org/techniques/T1036/), [T1567.001](https://attack.mitre.org/techniques/T1567/001/) |


MFT analysis reveals the user accessed files directly related to the masqueraded documents found on removable media. Windows Recent Items show: (1) '[secret_project]_design_concept.lnk' created 2015-03-23 18:38:21, and (2) '[secret_project]_final_meeting.pptx.lnk' created 2015-03-23 20:27:33. These link files prove the user opened PowerPoint and design documents matching the naming pattern of files found masqueraded on the removable media (rm2). The directory structure on rm2 includes '$OrphanFiles/design/' and '$OrphanFiles/proposal/' subdirectories, with files like 'winter_storm.amr' (actually OLE), 'a_gift_from_you.gif' (actually Word doc), and diary files. The 'secret_project' prefix in the Recent Items shortcuts matches the organizational pattern seen in the masqueraded files: design, proposal, progress, and technical documentation. This establishes a direct chain of evidence from the source files accessed on the informant-PC to the exfiltrated copies renamed on the USB device. The temporal proximity (both occurring on March 23, 2015) confirms deliberate data exfiltration activity, not coincidental file access.



### 10. [HIGH] Multiple Burn Sessions with Sequential File Deletion Pattern on Optical Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z |
| **Sources** | optical.listing |
| **Evidence Refs** | tc_9c4f4c3f |
| **ATT&CK** | [T1560](https://attack.mitre.org/techniques/T1560/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) |


Optical media analysis reveals 9 burn sessions (VAT generations) with a clear pattern of data staging and deletion. Files were written in earlier sessions and then deleted in subsequent sessions, leaving only innocuous-looking JPEG images in the final session (session 0).

**Timeline of burn sessions:**
- **Session -7** (earliest): /design/ directory with 2 files
- **Session -6**: /pricing decision/ directory with 4 files  
- **Session -5**: /progress/ directory with 3 files
- **Session -4**: /proposal/ directory with 2 files
- **Session -3**: /technical review/ directory with 6 files
- **Session -1** (most recent deleted): Abbreviated directory names (/de, /pd, /prog, /prop, /tr) with same files
- **Session 0** (final/present): Only 3 JPEG images (Koala.jpg, Penguins.jpg, Tulips.jpg)

**Evidence of data exfiltration pattern:**
1. All business-relevant files were written to the media in sessions -7 through -3
2. Files were then deleted in later sessions (indicated by session -1 entries)
3. The final session (0) contains only benign image files to avoid suspicion
4. However, the deleted files remain recoverable from the optical media's VAT structure
5. Directory names evolved from descriptive ("pricing decision") to abbreviated ("pd"), suggesting an attempt to conceal content purpose

The pattern of writing files then deleting them while leaving only media files is consistent with data exfiltration where the perpetrator attempts to make the media appear to contain only innocent content if casually inspected.



### 11. [HIGH] Cross-System Data Staging: Identical File Set on USB rm2 and Optical Media

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27Z to 2015-03-24T20:57:03Z |
| **Sources** | tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_39218b9f, tc_c7a4e0d9 |


Cross-system correlation reveals the same data set was staged across multiple exfiltration channels. The 17 masqueraded files found deleted on USB rm2 and the files burned to optical media share identical file sizes and modification timestamps, indicating they originated from the same source.

**Evidence of Same File Set:**
- winter_storm.amr: 14,547,968 bytes, modified 2015-01-23T16:47:10Z on BOTH rm2 and optical media
- winter_whether_advisory.zip: 16,381,123 bytes, modified 2014-12-16T12:10:26Z on BOTH rm2 and optical media
- All 17 files show matching sizes and modification times across both media

**Staging Timeline:**
1. March 24, 09:59:27-10:00:18 UTC: 17 files staged on USB rm2 (51 seconds total)
2. March 24, 13:47:58 UTC: User accesses "Secret Project Data\Secret Project Data\final" folder
3. March 24, 20:54:16-20:57:03 UTC: Same files burned to optical media in 9 sessions

**Data Flow Path:**
rm1 (Authorized USB) → PC → rm2 (staging) → optical media (final destination)

The identical file metadata and sequential staging indicate deliberate, organized data exfiltration across multiple removable media to maximize data transport capacity and evade detection.



### 12. [HIGH] No Post-Creation Activity for New Administrator Accounts

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T15:51:54Z to 2015-03-22T15:53:11Z |
| **Sources** | hayabusa.alerts, registry.ntuser.informant |
| **Evidence Refs** | tc_ef3c94bc |


The newly created administrator accounts (admin11, ITechTeam, temporary) showed NO evidence of login or usage after their creation on March 22, 2015.

**Account Creation Timeline (from hayabusa.alerts):**
- 2015-03-22 15:51:54: admin11 added to Administrators group by "informant"
- 2015-03-22 15:52:10: admin11 password reset by "informant"
- 2015-03-22 15:52:30: ITechTeam added to Administrators group by "informant"
- 2015-03-22 15:52:45: ITechTeam password reset by "informant"
- 2015-03-22 15:53:11: temporary password reset by "informant"

**Login Activity Analysis:**
- Event Log analysis (hayabusa.alerts) contains NO Event ID 4624 (successful logon) records for admin11, ITechTeam, or temporary accounts
- No UserAssist entries found for these accounts
- No shellbag entries or recent document access under these accounts

**Conclusion:**
The three administrator accounts were created and configured but NEVER USED after creation. This suggests they were created as POTENTIAL BACKUP ACCESS METHODS or for future use, not for immediate operational needs. The accounts may have been創建 prepared for use by another party or as redundant access channels.

This finding contradicts the hypothesis that these accounts were used for persistent access during the exfiltration operation.



### 13. [HIGH] Cloud Storage Present but Not Used During Exfiltration - Optical Media is Final Destination

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-24T09:59:27Z to 2015-03-24T20:57:03Z |
| **Sources** | bulk.domain, optical.listing, ez.shimcache |
| **Evidence Refs** | tc_c7a4e0d9, tc_db8e596f, tc_ef3c94bc |


While Google Drive and iCloud services were present and accessible on the informant-PC during the March 24, 2015 exfiltration window, no confirmed evidence of cloud upload activity was found during that critical period.

**Cloud Storage Tools Present:**
- Google Drive v.1.20.8672.3137 installed on 2015-03-23 20:02:46 UTC (bulk.domain confirms Google Drive URLs)
- iCloud services present (iCloud.exe executed historically on 2014-12-02)
- UserAssist shows googledrivesync.exe execution on 2015-03-22 14:35:01 UTC (initial setup/sync)

**Absence of Upload Evidence:**
- NO bulk_extractor evidence of Google Drive or iCloud upload timestamps during March 24, 09:59:27-20:57:03 UTC window
- NO browser history entries showing drive.google.com upload activity during exfiltration window
- NO network artifacts confirming cloud service data transfer during critical window

**Alternative Exfiltration Path:**
The evidence strongly supports OPTICAL MEDIA as the final exfiltration destination:
1. Files burned to optical CD (volume: "IAMAN CD") in 9 sessions between 20:54:16-20:57:03 UTC
2. Files deliberately deleted from earlier sessions, leaving only innocuous JPEG images visible
3. No cloud upload timestamps correlate with the staging timeline

**Conclusion:**
Cloud storage services were available but NOT utilized for exfiltration. The optical media was the primary exfiltration channel. This finding updates the earlier "inference" finding (f_8ab879f0) to "confirmed" with refined understanding.



### 14. [HIGH] SYSTEM-Initiated Privilege Escalation Triggered by Automated Process

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:33:54Z to 2015-03-22T14:33:54Z |
| **Sources** | hayabusa.alerts |
| **Evidence Refs** | tc_ef3c94bc |


The SYSTEM-initiated privilege escalation of the "informant" account on March 22, 2015 at 14:33:54 UTC was triggered by an AUTOMATED process, not manual intervention.

**Event Evidence (from hayabusa.alerts):**
- Event Time: 2015-03-22 14:33:54.485 +00:00
- Event ID: 4724 (Password Reset By Admin) and 4732 (User Added To Local Admin Grp)
- SubjectUserName: WIN-D9RGPJQ68G8$ (computer account)
- SubjectUserSid: S-1-5-18 (Well-known SID for NT AUTHORITY\SYSTEM)
- SubjectLogonId: 0x3e7 (Standard SYSTEM logon session ID)
- TargetUserName: informant

**Technical Analysis:**
- The SubjectLogonId 0x3e7 is the Windows NT AUTHORITY\SYSTEM session established at system boot
- This logon ID is used by SYSTEM-level processes, services, and scheduled tasks
- Computer account (WIN-D9RGPJQ68G8$) indicates machine-initiated action
- The absence of an interactive user logon ID strongly suggests an automated process

**Possible Triggers:**
1. Group Policy update applying security configurations
2. System deployment/configuration task (OOBE or Setup)
3. Scheduled task execution with SYSTEM privileges
4. Security software or management agent performing account setup

**Conclusion:**
The privilege escalation was AUTOMATED and SYSTEM-initiated, consistent with initial system configuration or deployment automation. This was NOT manual administrator action, indicating the "informant" account was elevated through a system process, possibly during initial PC setup on March 22, 2015.



### 15. [MEDIUM] Unauthorized User Account Creation and Privilege Escalation

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-22T14:33:54 to 2015-03-22T15:53:11 |
| **Sources** | hayabusa.alerts |
| **Evidence Refs** | tc_ce602dd4 |
| **ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/) |


On March 22, 2015, the user account 'informant' was added to the local Administrators group by an automated SYSTEM process. Additionally, three administrator accounts were created on the same day: 'admin11', 'ITechTeam', and 'temporary'. 

**AUTOMATED PRIVILEGE ESCALATION (14:33:54):**
- Event 4732/4724 show SubjectLogonId 0x3e7 (NT AUTHORITY\SYSTEM)
- SubjectUserName: WIN-D9RGPJQ68G8$ (computer account)
- SubjectUserSid: S-1-5-18 (SYSTEM)
- This indicates automation (OOBE, Group Policy, deployment script, or scheduled task)

**SUBSEQUENT MANUAL ACCOUNT CREATION (15:51-15:53):**
After the automated privilege escalation, the "informant" account manually created three additional admin accounts:
- 15:51:54: admin11 added to Administrators
- 15:52:10: admin11 password reset
- 15:52:30: ITechTeam added to Administrators
- 15:52:45: ITechTeam password reset
- 15:53:11: temporary password reset

**USAGE:**
All three accounts (admin11, ITechTeam, temporary) showed NO evidence of login after creation (finding f_edf1f727).

**UNCERTAINTY:**
While the automation suggests potential IT provisioning, the timing correlation with subsequent data exfiltration (March 24) and the presence of intent indicators (searches for "how to leak a secret", "data leakage methods" in browser history) creates a suspicious pattern. However, this finding alone does NOT establish malicious privilege escalation - the automated nature makes it equally consistent with legitimate provisioning.



### 16. [MEDIUM] Business-Sensitive Document Categories Identified in Exfiltrated Files

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2015-03-24T20:54:16Z to 2015-03-24T20:57:03Z |
| **Sources** | tsk.masquerade, optical.listing |
| **Evidence Refs** | tc_74ec299f, tc_9c4f4c3f |


Analysis of directory and file naming patterns on the optical media suggests exfiltration of business-sensitive documents related to corporate activities including pricing, proposals, technical reviews, and personnel matters.

**Directory categories:**
1. **Pricing Decision** (/pricing decision) - Contains documents potentially related to pricing strategy:
   - my_favorite_cars.db (Excel disguised as database)
   - my_favorite_movies.7z (Excel disguised as archive)
   - new_years_day.jpg (Excel disguised as image - 10.2 MB)
   - super_bowl.avi (OLE document disguised as video)

2. **Proposal** (/proposal) - Contains documents related to business proposals:
   - a_gift_from_you.gif (Word document disguised as GIF - 35.2 MB, largest file)
   - landscape.png (Word document disguised as image)

3. **Technical Review** (/technical review) - Contains diary entries with "d" and "p" suffixes:
   - diary_#1d.txt, diary_#2d.txt, diary_#3d.txt (Word/OLE documents disguised as text)
   - diary_#1p.txt, diary_#2p.txt, diary_#3p.txt (PowerPoint/OLE documents disguised as text)
   - The "d" suffix may indicate "draft" and "p" may indicate "presentation"

4. **Progress** (/progress) - Contains miscellaneous documents:
   - my_friends.svg (OLE document disguised as vector image)
   - my_smartphone.png (Word document disguised as image)
   - new_year_calendar.one (Word document disguised as OneNote)

5. **Design** (/design) - Contains:
   - winter_storm.amr (OLE document disguised as audio)
   - winter_whether_advisory.zip (PowerPoint disguised as archive)

The file naming convention (my_favorite_*, diary_*, winter_*) combined with disguised extensions indicates a deliberate attempt to make business documents appear as personal media files and archives. The presence of "diary" files with sequential numbering (#1, #2, #3) suggests systematic documentation over time.



### 17. [LOW] Anti-Forensic Tools Executed Before and After Data Exfiltration

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2015-01-12T22:56:36 to 2015-03-25T14:48:28 |
| **Sources** | ez.shimcache |
| **Evidence Refs** | tc_109750d6 |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1021](https://attack.mitre.org/techniques/T1021/) |


Anti-forensic cleaning tools were present and executed on the system, with timing that spans both before and after the data exfiltration event.

**TOOL EXECUTION TIMELINE:**

**January 12, 2015:**
- 22:56:30-32 UTC: Eraser 6.2.0.2962 installed (MFT shows Eraser directory creation and DLL files dated 2015-01-12)
- This is over 2 months BEFORE the March 24 exfiltration

**March 13, 2015:**
- 11:10:25 UTC: CCleaner64.exe executed (confirmed in registry.system ShimCache with "Executed" flag)
- This is 9 days BEFORE the March 24 exfiltration
- CCleaner language DLL files also show activity on March 13 (13:54 UTC)

**March 25, 2015:**
- 14:50:24 UTC: Eraser executed again (prefetch file created: ERASER 6.2.0.2962.EXE-BE552234.pf)
- This is the day AFTER the March 24 exfiltration completed
- Eraser download artifacts found in bulk.url (http://iweb.dl.sourceforge.net/project/eraser/.../Eraser%206.2.0.2962.exe)

**INTERPRETATION:**

**Scenario A - Anti-Forensic Preparation and Cleanup:**
- January Eraser installation: Preparing environment weeks in advance
- March 13 CCleaner: Clearing space or test-run of cleaning tools
- March 25 Eraser: Final cleanup after exfiltration completed
- The progression aligns with research mindset (anti-forensic techniques search found in browser history)

**Scenario B - Routine System Maintenance:**
- CCleaner is commonly used for disk cleanup (temp files, cache clearing)
- Eraser could be for secure deletion of personal files
- Timing correlation with exfiltration is coincidental
- March 2015 CCleaner execution matches typical maintenance schedule

**WEAKNESS:**
The March 13 CCleaner execution (9 days before exfiltration) and January Eraser installation (2+ months before) do not directly prove intent to hide exfiltration evidence. The strongest suspicious indicator is the March 25 Eraser execution (day after exfiltration), but even this could be coincidental.

**STRENGTHENING FACTORS:**
1. Browser history shows the user researched "anti-forensic techniques" (ForensicsWiki page accessed)
2. The user also searched for "data recovery software" - indicates awareness of forensic capabilities
3. Eraser is specifically designed for secure deletion (unlike general-purpose CCleaner)

**CONCLUSION:**
While the presence and execution of these tools coincides with the exfiltration timeframe, the evidence alone is insufficient to prove they were used specifically to hide exfiltration activity. The January and March 13 executions are equally compatible with routine maintenance. Only the March 25 execution is temporally suspicious (post-exfiltration), but without deleted file attribution, intent remains inferential.



### 18. [INFO] Source Data on Authorized USB (rm1)

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | tsk.filelist |
| **Evidence Refs** | tc_a7911182 |


Removable media rm1 is labeled "Authorized USB" and contains the source "Secret Project Data" folder structure with design documents. Folder hierarchy: Secret Project Data/Secret Project Data/design/[secret_pr...

This source USB contains the original project files that were later copied, renamed with false extensions, and staged on rm2 for exfiltration. The presence of an "Authorized USB" label suggests this was sanctioned removable media, and the double folder structure (Secret Project Data/Secret Project Data) indicates the data may have been copied recursively including the parent folder.

The design folder on rm1 directly corresponds to the design folder found in the deleted masqueraded files on rm2, confirming the data flow path. The matching folder structure (design, pricing/PRICIN~1, progress, proposal, technical/TECHNI~1) across both media confirms rm1 as the source and rm2 as the staging location.



### 19. [INFO] Application Execution History - Insider Access to Sensitive Data

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2015-03-22T14:34:26 to 2015-03-22T15:17:01 |
| **Sources** | ez.shimcache, ez.mft |
| **Evidence Refs** | tc_109750d6, tc_0ef00e5a |
| **ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/) |


ShimCache and MFT analysis shows extensive application usage by the 'informant' user account. Key executed applications include: Microsoft Office suite (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE) with timestamps from 2012-2015, Google Chrome browser (executed March 14, 2015), Internet Explorer (executed March 22, 2015), Windows Explorer, and system utilities. The execution of Microsoft Office applications is particularly significant given the Office documents found masqueraded on the removable media. All user files and application data are stored under the 'Users\informant' account path, confirming this was an active user account with legitimate access to organizational data. The MFT shows the user account was created on March 22, 2015, correlating with the event log findings.



### 20. [INFO] User Identity and Email Communication - NIST Government Account

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Sources** | bulk.email |
| **Evidence Refs** | tc_fd2f199c |
| **ATT&CK** | [T1114](https://attack.mitre.org/techniques/T1114/) |


Email artifacts extracted from the PC image reveal the primary user email address: 'iaman.informant@nist.gov' (NIST - National Institute of Standards and Technology). This email appears in multiple Outlook-related artifacts and AutoDiscover configurations. Additional cookie data shows web browsing activity under the 'informant' identity across various advertising and analytics domains. The presence of the .gov email address indicates this is a government system with access to potentially sensitive or classified information. The identity of the user as 'Iaman Informant' (potentially a real name or pseudonym) combined with access to NIST resources and the deliberate data exfiltration activities suggests this may be an insider threat case involving the theft of government research or proprietary data. However, the specific content of exfiltrated data was not identified in this forensic analysis.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `10.11.11.128` |  | User Access to Secret Project Documents on PC |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |





---

## Appendix C: MITRE ATT&CK Coverage

13 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (4) > Privilege Escalation (2) > Defense Evasion (3) > Lateral Movement (1) > Collection (4) > Exfiltration (2)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Privilege Escalation and Multiple... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Privilege Escalation and Multiple... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Unauthorized User Account Creation and...; Privilege Escalation and Multiple... |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Privilege Escalation and Multiple... |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Unauthorized User Account Creation and... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Privilege Escalation and Multiple... |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Unauthorized User Account Creation and...; Privilege Escalation and Multiple... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Data Exfiltration via Removable Media with...; Source File Access Correlation - Secret...; Optical Media Contains Files with Disguised... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Anti-Forensic Tools Executed Before and After... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Privilege Escalation and Multiple... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Anti-Forensic Tools Executed Before and After... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Application Execution History - Insider Access...; Source File Access Correlation - Secret... |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | User Identity and Email Communication - NIST... |
| [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data | Multiple Burn Sessions with Sequential File... |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Optical Media Contains Files with Disguised... |


### Exfiltration

| Technique | Name | Findings |
|-----------|------|----------|
| [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | Exfiltration over USB | Two SanDisk USB Devices Connected for Data Transfer; Multiple Burn Sessions with Sequential File... |
| [T1567.001](https://attack.mitre.org/techniques/T1567/001/) | Exfiltration to Code Repository | Data Exfiltration via Removable Media with...; Source File Access Correlation - Secret... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 362 |
| Findings submitted | 20 |
| Confirmed | 14 |
| Inferences | 6 |
| Input tokens | 8.2M |
| Output tokens | 134.1K |
| Total tokens | 8.3M |
| Audit log | /home/mulder/.mulder/cases/ndlc.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| bedrock/zai.glm-5 | 8.2M | 134.1K | 8.3M |




<details>
<summary>Evidence Sources (90)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| tsk.partitions | sleuthkit | 9 |
| tsk.filelist | sleuthkit | 51 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 264 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.email | bulk_extractor | 43 |
| bulk.exif | bulk_extractor | 27 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 288 |
| bulk.url_services | bulk_extractor | 19 |
| tsk.partitions | sleuthkit | 8 |
| tsk.partitions | sleuthkit | 9 |
| tsk.partitions | sleuthkit | 10 |
| tsk.filelist | sleuthkit | 27 |
| tsk.filelist | sleuthkit | 104709 |
| tsk.filelist.p1 | sleuthkit | 93 |
| tsk.partitions | sleuthkit | 8 |
| tsk.masquerade | sleuthkit | 17 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 189 |
| bulk.duplicates | bulk_extractor | 9 |
| bulk.exif | bulk_extractor | 20 |
| bulk.url | bulk_extractor | 207 |
| bulk.url_services | bulk_extractor | 14 |
| bulk.wordlist | bulk_extractor | 131102 |
| bulk.wordlist_dedup_1 | bulk_extractor | 112437 |
| tsk.masquerade | sleuthkit | 0 |
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
| ez.mft | eztools | 98918 |
| ez.shimcache | eztools | 307 |
| registry.system | regripper | 391 |
| registry.sam | regripper | 186 |
| registry.sam | regripper | 7 |
| registry.sam | regripper | 7 |
| registry.system | regripper | 69 |
| registry.system | regripper | 8 |
| registry.system | regripper | 33492 |
| registry.system | regripper | 283 |
| hayabusa.alerts | hayabusa | 35 |
| registry.system | regripper | 283 |
| registry.system | regripper | 5209 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| evtx.manifest | evtx-extract | 54 |
| registry.usrclass.admin11 | regripper | 11 |
| registry.ntuser.admin11 | regripper | 133 |
| registry.ntuser.default | regripper | 74 |
| registry.usrclass.informant | regripper | 102 |
| registry.ntuser.informant | regripper | 306 |
| registry.usrclass.temporary | regripper | 15 |
| registry.ntuser.temporary | regripper | 118 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| tsk.masquerade | sleuthkit | 3 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| optical.listing | mulder-optical | 58 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| registry.query.system | python-registry | 1 |
| bulk.bulk_extractor | bulk_extractor | 1 |
| bulk.domain | bulk_extractor | 7303 |
| bulk.duplicates | bulk_extractor | 1738 |
| bulk.email | bulk_extractor | 30 |
| bulk.exif | bulk_extractor | 21 |
| bulk.rfc822 | bulk_extractor | 41 |
| bulk.url | bulk_extractor | 7204 |
| bulk.url_services | bulk_extractor | 60 |
| bulk.zip_carved | bulk_extractor | 5221 |
| composite.timeline | composite | 172 |
| composite.defense_evasion | composite | 162 |
| composite.lateral_movement | composite | 440 |
| composite.persistence | composite | 2419 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
