# Accuracy Report: NDLC (NIST CFReDS Data Leakage Case 2015)

Mulder's autonomous findings evaluated against the [published answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) for the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html).

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 12 | 60% |
| PARTIAL | 6 | 30% |
| MISSED | 1 | 5% |
| FALSE POSITIVE | 1 | 5% |

**Effective accuracy: 60% full match, 90% detection rate (found at least related evidence), 5% false positive rate.**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | Suspect identity: "Iaman Informant" (iaman.informant@nist.gov) | FOUND | Correctly identified through SAM registry, resignation letter, Outlook OST references, RM2 volume label "IAMAN $_@", and bulk_extractor carved email data. Six independent attribution sources cited. |
| 2 | PC OS: Windows 7 Ultimate 64-bit, standalone WORKGROUP | PARTIAL | Identified as "Windows 7 Professional (64-bit) machine named 'informant-PC' in a WORKGROUP configuration." The OS edition is incorrect: ground truth specifies Ultimate, agent reported Professional. Computer name and WORKGROUP configuration correctly identified. |
| 3 | USB Device 1: SanDisk Cruzer Fit, S/N 4C530012450531101593, exFAT, "Authorized USB" | FOUND | Fully identified including serial number, volume label, filesystem, and connection timestamps via USBSTOR registry and System EVTX. |
| 4 | USB Device 2: SanDisk Cruzer Fit, S/N 4C530012550531106501, FAT32, "IAMAN $_@" | FOUND | Fully identified including serial number, volume label, dual-partition structure (NTFS+FAT32), and connection timestamps. |
| 5 | RM3: CD-ROM, UDF filesystem, formatted March 24, 2015 (16:53:17 UTC) | PARTIAL | Identified as "UDF-formatted CD-ROM created on March 26, 2015" with ExifTool metadata and HL-DT-ST DVD+-RW GT80N drive identification. Filesystem type and drive correctly identified, but creation date is wrong: answer key's UDF descriptor timestamp shows 2015-03-24 16:53:17, not March 26. |
| 6 | Five Secret Project documents exfiltrated to USB | FOUND | All five documents correctly identified by filename, file size, and location on both RM1 and RM2 NTFS partition. Exact byte sizes matched (35,226,880; 16,381,123; 14,547,968; 6,484,502 bytes). |
| 7 | File masquerading: Documents renamed with false extensions on RM2 FAT32 | PARTIAL | Four disguised copies identified with exact original-to-fake filename mappings (e.g., detailed_proposal.docx → "a_gift_from_you.gif"). Internal OOXML ZIP structures confirmed true file types. However, the answer key documents 22 renamed files (4 on D-2, 18 on D-1) and 17 recoverable disguised files on RM2's FAT32 partition. Agent found 4 of 22 mappings; technique correctly detected but coverage incomplete. |
| 8 | Anti-forensics tools: CCleaner and Eraser deployed | FOUND | Both tools fully documented: CCleaner 5.04 (ShimCache entry #61, installed/used/uninstalled Mar 13), Eraser 6.2.0.2962 (installed Mar 25, System Restore point "Installed Eraser 6.2.0.2962" at 14:57:27). |
| 9 | Search history reveals premeditation (leakage methods, anti-forensics) | FOUND | Extensive reconstruction from bulk_extractor carved URLs. Specific search terms matched: "information leakage cases" (47 hits), "anti-forensic tools" (85 hits), "file sharing and tethering" (491 hits), "windows event logs" (61 hits), "external device and forensics" (65 hits). |
| 10 | Google Drive sync installed for cloud exfiltration | FOUND | googledrivesync.exe identified in ShimCache with execution flag and compilation date. Google Drive sync folder at Users/informant/Google Drive/ with deleted sync databases. Prefetch GOOGLEDRIVESYNC.EXE-841A0D94.pf corroborates. |
| 11 | iCloud setup downloaded (secondary cloud channel) | FOUND | icloudsetup.exe identified in ShimCache, downloaded March 23, 2015 within 20 seconds of a Google Drive sync download. |
| 12 | USB connection timestamps via EVTX System log | FOUND | System EVTX USBSTOR driver installation at 18:31:10 for Device 1 on March 23. Device 2 first connection at 13:58:32 on March 24. Cross-correlated with registry timestamps. |
| 13 | Exfiltration timeline: Feb 15 bulk copy (42-second window) | FOUND | Exact reconstruction: "bulk copy operation transferring five proprietary documents to the USB media. The filesystem timeline records all five files between 16:51:38 and 16:52:20, a 42-second window consistent with a single drag-and-drop operation." |
| 14 | Anti-forensics: CCleaner deployed but did not clean (launched and closed without action) | FALSE POSITIVE | Agent claimed "CCleaner's execution effectively destroyed four categories of user activity artifacts — browser history, Jump Lists, LNK files, and Shellbags." The answer key explicitly states CCleaner "was closed after doing nothing." Furthermore, the answer key shows all four artifact categories (browser history, JumpLists, LNK files, ShellBags) DO exist in the evidence. The agent incorrectly attributed artifact absence to CCleaner when the tool was never actually run. |
| 15 | Systematic file deletion on RM2 FAT32 (Mar 24, 09:54-10:00) | FOUND | Exact timeframe captured: "systematically deleted all remaining organized files on RM2's FAT32 partition between 09:54:54 and 10:00:18." |
| 16 | RM3 contains government documents matching Secret Project content | PARTIAL | Report identifies RM3 content as "government IT governance DOCX document with embedded IREAP/UMER references matching the Secret Project documents" but does not enumerate all files on the disc or match them to the specific 5 documents. |
| 17 | Files opened in RM2 (list all accessed files) | PARTIAL | Report identifies the Word temporary file (~$ecret_project]_proposal.docx) created at 14:37:52 proving document review, and the 22 personal images batch-deleted. Does not provide a complete list of all files opened/accessed on RM2. |
| 18 | Network drive directories traversed | MISSED | Report does not identify any network drive access or traversal. The answer key documents directory browsing on the company's secured network drives. No network share artifacts were surfaced. |
| 19 | Email communication with spy.conspirator@nist.gov | PARTIAL | Report identifies the email address iaman.informant@nist.gov and Outlook OST references but does not identify the spy.conspirator@nist.gov correspondent or the specific email exchanges. |
| 20 | FAT32 timezone offset (local time vs UTC) | PARTIAL | Report correctly notes: "The modification timestamps on the FAT32 partition are consistently one hour later than the NTFS timestamps, consistent with FAT32 storing local time versus NTFS storing UTC in a UTC+1 timezone environment." This is identified but the timezone is assessed as UTC+1 when the ground truth specifies UTC-5 (Eastern Time). |

---

## Findings Beyond the Answer Key

The agent identified several findings not explicitly covered by the published ground truth:

| Finding | Assessment |
|---------|------------|
| Resignation letter on desktop establishing departing-employee context | Legitimate. Supports insider threat motive assessment. |
| IREAP/UMER (University of Maryland) project identification from document metadata | Legitimate. Identifies the specific research program whose IP was stolen. |
| Kodak DC260 camera EXIF metadata linking personal photos across RM2 and RM3 | Legitimate. Cross-media correlation supporting single-operator attribution. |
| "security checkpoint cd-r" search query revealing physical exfiltration planning | Legitimate. Explains why CD-ROM was chosen as final exfiltration medium. |
| ShimCache execution timeline with 292 entries providing comprehensive tool history | Legitimate. Core evidence source that survived anti-forensics cleanup. |
| Volume serial numbers cross-referenced across registry and filesystem metadata | Legitimate. Standard forensic correlation technique correctly applied. |

---

## False Positive Handling

**One false positive identified in post-verification.** The CCleaner artifact-destruction claim (item 14) attributes forensic artifact loss to a tool that the answer key explicitly states was launched and closed without performing any cleaning action. The answer key confirms that browser history, JumpLists, LNK files, and ShellBags all exist in the evidence, contradicting the agent's claim that they were destroyed.

The remaining 32 findings are either correct observations supported by multi-source evidence or appropriately hedged inferences (4 findings at inference confidence, all clearly labeled). The report explicitly noted gaps rather than speculating: Google Drive exfiltration was characterized as "likely but unconfirmed" since sync databases were deleted; the 12 additional disguised files on RM2 were flagged as potential additional exfiltration but not claimed without file content verification.

---

## Analysis of Misses and Errors

### CCleaner false attribution (item 14)

The agent attributed destruction of browser history, JumpLists, LNK files, and ShellBags to CCleaner execution. The answer key explicitly states CCleaner "was closed after doing nothing" and confirms all four artifact categories exist in the evidence. This represents a false causal attribution. The likely explanation: the agent observed that certain artifact parsers returned sparse or empty results for specific time windows and incorrectly inferred CCleaner was responsible, without verifying that (a) the artifacts do exist for other time windows, and (b) the tool was never actually run. This is the investigation's single false positive.

### OS edition error (item 2)

The agent identified Windows 7 Professional instead of Windows 7 Ultimate. The registry key at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` contains the definitive ProductName value. The error suggests the agent read a different indicator or misinterpreted the value.

### RM3 creation date error (item 5)

The agent reported the CD-ROM creation date as March 26, 2015 when the UDF descriptor timestamp at file offset 0x1017A clearly encodes 2015-03-24 16:53:17. The 2-day discrepancy may result from reading a different metadata field (e.g., ExifTool output vs. raw UDF descriptor).

### File masquerading coverage (item 7)

The agent correctly identified the file masquerading technique and provided 4 exact filename mappings, but the answer key documents 22 renamed files from the USN Journal and 17 recoverable disguised files on RM2. The investigation detected the pattern but did not exhaustively enumerate all instances.

### Network drive traversal (item 18)

The answer key documents the suspect browsing company network drives at `\\10.11.11.128\secured_drive` with extensive ShellBag, JumpList, and LNK file evidence. The report found no evidence of network share access. The relevant artifacts (ShellBags, JumpLists, LNK files) DO exist in the evidence per the answer key, so this miss resulted from incomplete artifact analysis rather than artifact destruction. This is the investigation's single complete miss.

### Email correspondence (item 19)

The Outlook OST file references were found but the actual email content (messages to/from spy.conspirator@nist.gov) was not extracted. The answer key documents 11+ email exchanges with full subjects and bodies recoverable from both the OST file and Windows Search database (Windows.edb). The `parse_pst` tool was available but either not applied to the OST file or did not yield the email thread details.

### Timezone assessment (item 20)

The report correctly identified the FAT32/NTFS timestamp discrepancy but assessed the offset as UTC+1 rather than the ground truth UTC-5 (Eastern Time). The answer key specifies "Set the timezone to (UTC-05) Eastern Time" with Daylight Time Bias +1. The report's forensic observation (timestamps differ) is correct but the timezone conclusion was wrong.

---

## Honest Assessment

### Strengths

- **Comprehensive timeline reconstruction.** The 6-phase timeline from October 2014 through March 2015 closely matches the answer key's detailed behavior sequence, with precise timestamps for each operational phase.
- **File masquerading detection.** Disguised documents were identified with correct original-to-fake mappings confirmed via internal OOXML structure analysis, demonstrating the technique detection even if coverage was incomplete.
- **Cross-media correlation.** Evidence was linked across all four devices (PC, RM1, RM2, RM3) through consistent IREAP/UMER markers, volume labels, and EXIF metadata.
- **USB device identification.** Both removable media devices fully identified with serial numbers, volume labels, filesystems, and connection timestamps cross-correlated across registry and EVTX sources.
- **Search history reconstruction.** Extensive web search history correctly recovered and categorized, demonstrating premeditated planning.

### Weaknesses

- **CCleaner false attribution.** The agent incorrectly claimed CCleaner destroyed multiple artifact categories when the answer key confirms the tool was launched and closed without performing any action. This is the investigation's single false positive.
- **Network drive analysis gap.** Network share access evidence (ShellBags, JumpLists, LNK files for `\\10.11.11.128\secured_drive`) was not surfaced despite existing in the evidence, representing the only complete miss.
- **Email content not extracted.** The Outlook OST was identified but not deeply parsed for the 11+ email exchanges with spy.conspirator@nist.gov.
- **Timezone error.** The FAT32/NTFS offset was observed but misinterpreted as UTC+1 instead of UTC-5 (Eastern Time).
- **RM3 creation date error.** Reported as March 26 when the UDF descriptor encodes March 24, 2015.
- **Incomplete file enumeration.** Only 4 of 22 renamed files identified; RM3 contents not exhaustively listed.

### Summary

The agent successfully reconstructed the insider threat operation across four evidence items in 1.7 hours, producing 33 findings. It correctly identified the suspect, the exfiltrated documents, the anti-forensics tools deployed, the multi-vector exfiltration strategy, and the operational timeline. The 60% full-match accuracy with 90% detection rate and one false positive demonstrates solid performance on an insider threat case requiring cross-device correlation and anti-forensics analysis, while highlighting areas for improvement in artifact completeness and causal reasoning.
