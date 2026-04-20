# NIST Data Leakage -- CFReDS 2015

## Scenario

The [NIST CFReDS Data Leakage Case](https://cfreds.nist.gov/all/NIST/DataLeakageCase) is a single-actor insider threat investigation. A NIST employee identified as "Iaman Informant" systematically exfiltrated classified "Secret Project Data" from a secured network share to removable media and cloud storage over a six-week period (February--March 2015), while simultaneously researching anti-forensic techniques to cover their tracks.

**Source:** [NIST CFReDS](https://cfreds.nist.gov/all/NIST/DataLeakageCase) (free download)

## Evidence Analyzed

| Evidence Type | Items | Description |
|---------------|-------|-------------|
| PC disk image (E01) | 1 | Suspect's Windows 7 x64 workstation (~20GB NTFS) |
| USB images (E01) | 2 | RM1 "Authorized USB" (exFAT), RM2 "IAMAN" (FAT32) |
| CD-R image (E01) | 1 | RM3 optical media with government documents and photos |

**Total evidence items classified:** 43 disk, 2 other

## Results

| Metric | Value |
|--------|-------|
| Findings | 10 (5 critical, 5 high) |
| Confirmed | 10 |
| Inference | 0 |
| Hypotheses ruled out | 1 |
| Tool calls | 167 |
| Wall-clock time | ~30 minutes |
| Evidence sources indexed | 8 |

### Findings

1. **[CRITICAL] Insider Threat: User "Iaman Informant" Exfiltrating Secret Project Data via USB** -- Complete Secret Project Data package on RM1 USB with Office temp files confirming editing. LNK files corroborate access.
2. **[CRITICAL] Google Drive Exfiltration via Personal Gmail** -- Google Drive Sync installed and configured with `iaman.informant.personal@gmail.com` (separate from work email). Prefetch confirms execution. Sync databases deleted to hide evidence.
3. **[CRITICAL] Premeditated Data Theft: Systematic Research on Leaking and Anti-Forensics** -- 900+ search queries for data theft methods, anti-forensic tools, and counter-investigation techniques. Precise Prefetch timestamp at 2015-03-25T14:31:53Z.
4. **[CRITICAL] Data Source: Secret Project from Network Share** -- LNK artifacts trace data to `\\10.11.11.128\SECURED_DRIVE` (mapped as V:). Timestamps: 2015-02-15T21:52:08Z through 2015-03-22T14:52:21Z.
5. **[CRITICAL] Resignation Letter Created After Anti-Forensic Cleanup** -- Created 2015-03-25T14:20:09Z, exported to XPS at 15:28:33Z, during same session as Eraser/CCleaner execution.
6. **[HIGH] Anti-Forensic Tool Installation: Eraser 6 and CCleaner** -- Both downloaded from internet (Zone.Identifier confirmed), installed, executed (Prefetch), then installers deleted.
7. **[HIGH] Deleted Data on USB RM2 (FAT32)** -- Orphan files in project-structure directories (design, pricing, progress, proposal, technical) including 6 diary files.
8. **[HIGH] CD-R (RM3) Contains Image Files** -- Used as additional exfiltration medium. User searched "cd burning method" 64 times. Windows Burn staging directory found.
9. **[HIGH] Eraser 6 Executed for Secure Deletion** -- Precise Prefetch execution timestamp 2015-03-25T14:50:14Z. Task list at `Eraser 6/Task List.ersy`. Confirmed file deletion activity.
10. **[HIGH] Prefetch Execution Timeline: Minute-by-Minute Cleanup Session** -- March 25 session reconstructed: Outlook 14:41, Eraser installer 14:50, CCleaner 14:58, Eraser execution 15:13, IE 15:22, resignation XPS 15:28.

### ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Defense Evasion | T1027 Obfuscation, T1070 Indicator Removal, T1070.004 File Deletion |
| Collection | T1005 Local Data, T1039 Network Shared Drive, T1074.001 Local Data Staging, T1119 Automated Collection |
| Exfiltration | T1052.001 Exfiltration over USB, T1567.002 Exfiltration to Cloud Storage, T1052 Physical Medium |
| Impact | T1485 Data Destruction |

## Ground Truth Comparison

The CFReDS Data Leakage Case has a [published answer key](https://cfreds.nist.gov/all/NIST/DataLeakageCase).

**Correctly identified:**
- Complete exfiltration chain: network share -> USB -> cloud storage -> CD-R
- All four evidence images analyzed with relevant artifacts extracted
- Anti-forensic tool usage (Eraser, CCleaner) with Prefetch execution timestamps
- Premeditation established through search history analysis
- Timeline reconstruction from Feb 15 through Mar 25, 2015 cleanup session
- Suspect identity and both work and personal email accounts confirmed
- Personal Gmail (`iaman.informant.personal@gmail.com`) distinguished from work email
- Multiple exfiltration vectors identified (USB, CD-R, Google Drive)
- Evidence of data wiping on RM2 USB drive
- Resignation letter timing correlated with cleanup session

**Not fully articulated:**
- The "temporary" user account created on March 22 is mentioned but not explored as a separate finding

## Output Files

- [`nist-data-leakage.report.md`](nist-data-leakage.report.md) -- Full markdown report
- [`nist-data-leakage.report.html`](nist-data-leakage.report.html) -- Self-contained HTML report
