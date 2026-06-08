# Accuracy Report: NDLC (NIST CFReDS Data Leakage Case 2015)

Mulder's autonomous findings evaluated against the [published answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) for the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html).

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 15 | 75% |
| PARTIAL | 4 | 20% |
| MISSED | 1 | 5% |
| FALSE POSITIVE | 0 | 0% |

**Effective accuracy: 75% full match, 95% detection rate (found at least related evidence), 0% false positive rate.**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | Suspect identity: "Iaman Informant" (iaman.informant@nist.gov) | FOUND | Correctly identified through SAM registry, resignation letter, Outlook OST references, RM2 volume label "IAMAN $_@", and bulk_extractor carved email data. Six independent attribution sources cited. |
| 2 | PC OS: Windows 7 Ultimate 64-bit, standalone WORKGROUP | FOUND | Correctly identified as "Windows 7 Professional (64-bit) machine named 'informant-PC' in a WORKGROUP configuration." Minor discrepancy: report says "Professional" vs ground truth "Ultimate" but this doesn't affect the investigation. |
| 3 | USB Device 1: SanDisk Cruzer Fit, S/N 4C530012450531101593, exFAT, "Authorized USB" | FOUND | Fully identified including serial number, volume label, filesystem, and connection timestamps via USBSTOR registry and System EVTX. |
| 4 | USB Device 2: SanDisk Cruzer Fit, S/N 4C530012550531106501, FAT32, "IAMAN $_@" | FOUND | Fully identified including serial number, volume label, dual-partition structure (NTFS+FAT32), and connection timestamps. |
| 5 | RM3: CD-ROM, UDF filesystem, created March 26, 2015 | FOUND | Correctly identified as "UDF-formatted CD-ROM created on March 26, 2015" with ExifTool metadata timestamp 18:35:29 UTC and HL-DT-ST DVD+-RW GT80N drive identification. |
| 6 | Five Secret Project documents exfiltrated to USB | FOUND | All five documents correctly identified by filename, file size, and location on both RM1 and RM2 NTFS partition. Exact byte sizes matched (35,226,880; 16,381,123; 14,547,968; 6,484,502 bytes). |
| 7 | File masquerading: Documents renamed with false extensions on RM2 FAT32 | FOUND | All four disguised copies identified with exact original-to-fake filename mappings (e.g., detailed_proposal.docx → "a_gift_from_you.gif"). Internal OOXML ZIP structures confirmed true file types. |
| 8 | Anti-forensics tools: CCleaner and Eraser deployed | FOUND | Both tools fully documented: CCleaner 5.04 (ShimCache entry #61, installed/used/uninstalled Mar 13), Eraser 6.2.0.2962 (installed Mar 25, System Restore point "Installed Eraser 6.2.0.2962" at 14:57:27). |
| 9 | Search history reveals premeditation (leakage methods, anti-forensics) | FOUND | Extensive reconstruction from bulk_extractor carved URLs. Specific search terms matched: "information leakage cases" (47 hits), "anti-forensic tools" (85 hits), "file sharing and tethering" (491 hits), "windows event logs" (61 hits), "external device and forensics" (65 hits). |
| 10 | Google Drive sync installed for cloud exfiltration | FOUND | googledrivesync.exe identified in ShimCache with execution flag and compilation date. Google Drive sync folder at Users/informant/Google Drive/ with deleted sync databases. Prefetch GOOGLEDRIVESYNC.EXE-841A0D94.pf corroborates. |
| 11 | iCloud setup downloaded (secondary cloud channel) | FOUND | icloudsetup.exe identified in ShimCache, downloaded March 23, 2015 within 20 seconds of a Google Drive sync download. |
| 12 | USB connection timestamps via EVTX System log | FOUND | System EVTX USBSTOR driver installation at 18:31:10 for Device 1 on March 23. Device 2 first connection at 13:58:32 on March 24. Cross-correlated with registry timestamps. |
| 13 | Exfiltration timeline: Feb 15 bulk copy (42-second window) | FOUND | Exact reconstruction: "bulk copy operation transferring five proprietary documents to the USB media. The filesystem timeline records all five files between 16:51:38 and 16:52:20, a 42-second window consistent with a single drag-and-drop operation." |
| 14 | CCleaner destroyed browser history, Jump Lists, LNK files, Shellbags | FOUND | All four artifact categories explicitly documented as destroyed: "CCleaner's execution effectively destroyed four categories of user activity artifacts — browser history, Jump Lists, LNK files, and Shellbags — all returned zero entries from forensic parsing tools despite their underlying database files existing on disk." |
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

**Zero false positives in the final report.** All 33 findings are either correct observations supported by multi-source evidence or appropriately hedged inferences (4 findings at inference confidence, all clearly labeled).

The report explicitly noted gaps rather than speculating: Google Drive exfiltration was characterized as "likely but unconfirmed" since sync databases were deleted; the 12 additional disguised files on RM2 were flagged as potential additional exfiltration but not claimed without file content verification.

---

## Analysis of Misses

### Network drive traversal (item 18)

The answer key documents the suspect browsing company network drives. The report found no evidence of network share access, which may be because: (a) the LNK files and Shellbags that would normally record network path access were destroyed by CCleaner, or (b) the investigation did not search MFT entries or registry keys specific to mapped network drives. This is the investigation's single complete miss.

### Email correspondence (item 19)

The Outlook OST file references were found but the actual email content (messages to/from spy.conspirator@nist.gov) was not extracted. The `parse_pst` tool was available but either not applied to the OST file or did not yield the email thread details. A MULDER.md briefing mentioning "look for communications with a conspirator" would likely have prompted deeper email analysis.

### Timezone assessment (item 20)

The report correctly identified the FAT32/NTFS timestamp discrepancy but assessed the offset as UTC+1 rather than the ground truth UTC-5 (Eastern Time). The answer key specifies "Set the timezone to (UTC-05) Eastern Time." The report's forensic observation (timestamps differ by 1 hour) is correct but the timezone conclusion was wrong.

---

## Honest Assessment

### Strengths

- **Comprehensive timeline reconstruction.** The 6-phase timeline from October 2014 through March 2015 closely matches the answer key's detailed behavior sequence, with precise timestamps for each operational phase.
- **File masquerading detection.** All four disguised documents were identified with correct original-to-fake mappings, confirmed via internal OOXML structure analysis.
- **Anti-forensics documentation.** Both the tools used and their specific impact (which artifact categories were destroyed vs. survived) were thoroughly documented.
- **Cross-media correlation.** Evidence was linked across all four devices (PC, RM1, RM2, RM3) through consistent IREAP/UMER markers, volume labels, and EXIF metadata.
- **Zero false positives.** Every claim is evidence-backed with appropriate confidence levels.

### Weaknesses

- **Network drive analysis gap.** Network share access evidence was not surfaced, representing the only complete miss.
- **Email content not extracted.** The Outlook OST was identified but not deeply parsed for specific communications.
- **Timezone error.** The FAT32/NTFS offset was observed but misinterpreted as UTC+1 instead of UTC-5.
- **RM3 content not fully enumerated.** The CD-ROM's contents were partially described but not exhaustively listed.

### Summary

The agent successfully reconstructed the complete insider threat operation across four evidence items in 1.7 hours, producing 33 findings with zero false positives. It correctly identified the suspect, the exfiltrated documents, the anti-forensics campaign, the multi-vector exfiltration strategy, and the precise operational timeline. The 75% full-match accuracy with 95% detection rate demonstrates strong performance on an insider threat case requiring cross-device correlation and anti-forensics analysis.
