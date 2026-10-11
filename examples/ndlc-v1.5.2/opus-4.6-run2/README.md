# NDLC on Claude Opus 4.6, run 2 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using `claude-opus-4-6` directly through the Anthropic API with extended thinking, run on the v1.5.2 release image. This is the reference run for the three open-weight models in this directory, which used the same evidence, prompts, tools and scoring rubric. The original v1.5.1 Opus run of this case is kept in [examples/ndlc](../../ndlc/).

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the earlier baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison, including a per-item table across all four v1.5.2 models.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 10 | 50% |
| PARTIAL | 8 | 40% |
| MISSED | 1 | 5% |
| FALSE POSITIVE | 2 | 10% |

**50% full match, 90% detection rate, 10% false positive rate.** One of three Opus runs on this image; see [run 1](../opus-4.6-run1/) (45% / 95% / 10%) and [run 3](../opus-4.6-run3/). One of its two false positives comes from the same harness defect as run 1 (issue #232, fixed after v1.5.2): the RM2 executor asked for the timeline and filesystem sources by name and received RM1's rows.

## What the Model Concluded

- Correctly framed the case as a premeditated departing-insider exfiltration by "Iaman Informant" (`iaman.informant@nist.gov`), reconstructed in six phases from the February 15 USB copy through the March 25 Eraser and CCleaner runs and the resignation letter, with every PC-side timestamp matching the answer key to the second.
- Named all five Secret Project documents with exact sizes on RM1, enumerated all 17 disguised copies on RM2's FAT32 partition with true types and four exact original-to-fake mappings, and traced the same 17 onto the "IAMAN CD" across nine UDF sessions hidden behind three Windows sample photos.
- Identified both SanDisk Cruzer Fit serials from the registry, the `\\10.11.11.128\secured_drive` share with its V: mapping and the two files opened from it, the local staging copy, 27 search terms with hit counts mapped to actions, and the Google Drive and iCloud installs with the cloud upload correctly held as unconfirmed.
- Got wrong: RM2 was given RM1's exFAT "Authorized USB" partition and February timeline (the source-name collision above), and CCleaner was credited with a "partially succeeded" cleanup plus a fictitious mid-March install built from ShimCache dates. Those are the two false positives. No timezone was stated, and the email correspondent was not found.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 120 (63 disk, 57 other) |
| Total tool calls | 500 |
| Findings | 24 (1 critical, 8 high, 6 medium, 4 low, 5 info), 4 hypotheses ruled out |
| Confirmed / Inference | 20 / 4 |
| False positives | 2 |
| Runtime | 69 minutes |
| Model | claude-opus-4-6 (extended thinking, effort max) |
| Tokens | 27K uncached input / 189K output (prompt-cache reads not counted) |
| Exit code | 0, all quality gates passed on the first attempt |
| Mulder | v1.5.2 |

## How It Was Run

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model claude-opus-4-6 --show-cli-stderr
```

## Evidence Dataset

| Field | Value |
|-------|-------|
| **Source** | [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) |
| **Answer Key** | [Published NIST ground truth (55 pages)](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) |
| **Accuracy Report** | [ACCURACY-REPORT.md](ACCURACY-REPORT.md) |

### Evidence Files

| File | Type | Size |
|------|------|------|
| cfreds_2015_data_leakage_pc.E01-.E04 | PC disk image (EnCase, 4 parts) | 7.3 GB |
| cfreds_2015_data_leakage_rm1.E01 | USB RM1 (exFAT, "Authorized USB") | 75 MB |
| cfreds_2015_data_leakage_rm2.E01 | USB RM2 (FAT32, "IAMAN $_@") | 243 MB |
| cfreds_2015_data_leakage_rm3_type3.E01 | CD-R RM3 (UDF) | 90 MB |

## Files in This Directory

| File | Description |
|------|-------------|
| `ndlc.report.md` | Full investigation report (Markdown) |
| `ndlc.report.html` | Investigation report (HTML with navigation) |
| `ndlc.audit.jsonl` | Structured tool execution audit log (552 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,225 lines) |
| `mulder.log` | MCP server tool execution log (167 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
