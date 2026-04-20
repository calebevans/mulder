# NIST Data Leakage -- CFReDS 2015

## Scenario

The [NIST CFReDS Data Leakage Case](https://cfreds.nist.gov/all/NIST/DataLeakageCase) is a single-actor insider threat investigation. A NIST employee identified as "Iaman Informant" systematically exfiltrated classified "Secret Project Data" from a secured network share to removable media and cloud storage over a multi-month period (December 2014 -- March 2015), while simultaneously researching anti-forensic techniques to cover their tracks.

**Source:** [NIST CFReDS](https://cfreds.nist.gov/all/NIST/DataLeakageCase) (free download, ~7.7 GB)
**Answer Key:** [NIST published answers](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) (60 questions with detailed answers)

## Evidence Analyzed

| Evidence Type | Items | Description |
|---------------|-------|-------------|
| PC disk image (E01) | 4 segments | Windows 7 x64 workstation (~20 GB NTFS) |
| USB images (E01) | 2 | RM1 "Authorized USB" (exFAT, 4 GB), RM2 "IAMAN $_@" (FAT32, 4 GB) |
| CD-R image (E01) | 1 | RM3 "IAMAN CD" (UDF, 700 MB) |

## Model Comparison

| Metric | Opus | Sonnet |
|--------|------|--------|
| Findings | 15 (6 crit, 7 high) | 14 (9 crit, 4 high) |
| Confirmed / Inference | 13 / 2 | 13 / 1 |
| Tool calls | 157 | 246 |
| Wall-clock time | ~23 min | ~34 min |
| Timeline start | 2015-03-22 | **2015-02-15** (found earlier USB access) |
| Earliest data staging | Not found | **2014-12-16** (LNK write time on USB) |
| Gov agency docs named | General reference | **NASA, NIH, LoC, DOE** specifically identified |
| Post-cleanup cloud sync | Not found | **Google Drive Sync ran after Eraser/CCleaner** |
| Anti-forensic detail | Tool identification | **Minute-by-minute March 25 cleanup timeline** |

**Opus** was faster and identified more total findings (15 vs 14), including the shared content between RM2 and RM3 as a dedicated finding. Conservative and thorough on tool-level artifacts.

**Sonnet** found deeper temporal evidence (December 2014 data staging, February 2015 first USB access), produced a more detailed anti-forensic timeline, and caught that Google Drive Sync executed *after* the cleanup tools -- meaning cloud exfiltration may have continued even as local evidence was being destroyed. The narrative reads like a professional forensic examiner's report with minute-by-minute chronology.

## Ground Truth Comparison

The CFReDS Data Leakage Case has a [published answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with 60 detailed questions and answers.

**Correctly identified (both models):**
- Complete exfiltration chain: network share -> USB -> cloud storage -> CD-R
- All four evidence images analyzed with relevant artifacts extracted
- Anti-forensic tool usage (Eraser, CCleaner) with Prefetch timestamps
- Premeditation established through search history analysis (900+ queries)
- Suspect identity (Iaman Informant, iaman.informant@nist.gov)
- Network share source (\\10.11.11.128\SECURED_DRIVE)
- Multiple exfiltration vectors (USB, CD-R, Google Drive, iCloud)
- Resignation letter correlated with cleanup session
- Evidence of data wiping on RM2 USB drive

**Sonnet additionally found:**
- December 2014 earliest data staging via LNK write timestamps
- Government agency documents named (NASA HQ, NIH, Library of Congress, DOE)
- Google Drive Sync active after anti-forensic cleanup
- Eraser Task List.ersy file at specific inode as actionable evidence

**Not fully articulated (both models):**
- Email exchange with spy.conspirator@nist.gov (Outlook OST not parsed)
- Volume Shadow Copy analysis (NIST questions 47-50)
- Windows Search database content (NIST questions 42-46)
- Sticky Notes content (NIST questions 40-41)

## Output Files

### Opus

- [`opus/nist-data-leakage.report.md`](opus/nist-data-leakage.report.md) -- Markdown report
- [`opus/nist-data-leakage.report.html`](opus/nist-data-leakage.report.html) -- HTML report
- [`opus/claude.log`](opus/claude.log) -- Claude Code session log

### Sonnet

- [`sonnet/nist-data-leakage.report.md`](sonnet/nist-data-leakage.report.md) -- Markdown report
- [`sonnet/nist-data-leakage.report.html`](sonnet/nist-data-leakage.report.html) -- HTML report
- [`sonnet/claude.log`](sonnet/claude.log) -- Claude Code session log
