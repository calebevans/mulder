# NDLC: NIST Data Leakage Case (CFReDS 2015)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html), an insider threat scenario involving premeditated exfiltration of proprietary research documents via USB, cloud storage, and optical media, with systematic anti-forensics countermeasures.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-ROM). No memory dumps, no network capture.

## Scenario

An employee ("Iaman Informant") at a technology company planned and executed the theft of proprietary research documents. The suspect researched data leakage methods and anti-forensics techniques, exfiltrated documents to multiple removable media devices with deliberate file masquerading, deployed cloud sync for a secondary exfiltration channel, and systematically destroyed forensic artifacts using CCleaner and Eraser before burning a final copy to CD-ROM.

## Key Findings

- **Proprietary documents exfiltrated:** 5 "Secret Project" documents (~74 MB) copied to USB media on Feb 15, 2015 in a 42-second window
- **File masquerading:** Documents renamed with false extensions (.gif, .amr, .png, .zip) on RM2 FAT32 partition to evade casual inspection
- **Multi-vector exfiltration:** USB (confirmed), Google Drive cloud sync (likely, sync databases deleted), CD-ROM (confirmed, burned Mar 26)
- **Premeditated anti-forensics:** Search history reveals deliberate research into "anti-forensic tools" (85 hits), "windows system artifacts" (79 hits), "investigation on windows machine" (64 hits)
- **Systematic artifact destruction:** CCleaner destroyed browser history, Jump Lists, LNK files, and Shellbags; Eraser used for secure file deletion
- **Timeline reconstructed:** Oct 2014 (planning) through Mar 26, 2015 (final CD-ROM exfiltration)
- **Attribution confirmed:** "Iaman Informant" (iaman.informant@nist.gov) via 6 independent evidence sources

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-ROM) |
| Evidence files | 8 images (E01 + 7z formats) |
| Evidence sources indexed | 88 (42 disk, 46 other) |
| Total tool calls | 723 |
| Findings | 33 (0 critical, 15 high, 7 medium, 0 low, 11 info) |
| Confirmed / Inference | 29 / 4 |
| False positives | 0 |
| MITRE ATT&CK techniques | 12 |
| Runtime | 1.7 hours |
| Model | claude-opus-4-6 |
| Total tokens | 330.3K |

## Evidence Dataset

| Field | Value |
|-------|-------|
| **Source** | [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) |
| **Answer Key** | [leakage-answers.pdf (55 pages)](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) |
| **Accuracy Report** | [ACCURACY-REPORT.md](ACCURACY-REPORT.md) |

### Evidence Files

| File | Type | Size |
|------|------|------|
| cfreds_2015_data_leakage_pc.E01-.E04 | PC disk image (EnCase, 4 parts) | 7.3 GB |
| cfreds_2015_data_leakage_pc.7z.001-.003 | PC disk image (DD, 3 parts) | 5.1 GB |
| cfreds_2015_data_leakage_rm1.E01 | USB RM1 (exFAT, "Authorized USB") | 75 MB |
| cfreds_2015_data_leakage_rm2.E01 | USB RM2 (NTFS+FAT32, "IAMAN $_@") | 243 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | CD-ROM RM3 (UDF) | 90 MB |

## Files in This Directory

| File | Description |
|------|-------------|
| `ndlc.report.md` | Full investigation report (Markdown) |
| `ndlc.report.html` | Investigation report (HTML with navigation) |
| `ndlc.audit.jsonl` | Structured tool execution audit log (773 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,920 lines) |
| `mulder.log` | MCP server tool execution log (1,768 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against published answer key |
