# NDLC on Claude Opus 4.6, run 3 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using `claude-opus-4-6` directly through the Anthropic API with extended thinking, run on the v1.5.2 release image. This is the reference run for the three open-weight models in this directory, which used the same evidence, prompts, tools and scoring rubric. The original v1.5.1 Opus run of this case is kept in [examples/ndlc](../../ndlc/).

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the earlier baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison, including a per-item table across all four v1.5.2 models.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 9 | 45% |
| PARTIAL | 10 | 50% |
| MISSED | 0 | 0% |
| FALSE POSITIVE | 1 | 5% |

**45% full match, 95% detection rate, 5% false positive rate.** The lowest false-positive count of the three Opus runs on this image; see [run 1](../opus-4.6-run1/) (45% / 95% / 10%) and [run 2](../opus-4.6-run2/) (50% / 90% / 10%). The only false positive is the one every run of every model makes: CCleaner credited with destroying browser history that the answer key says was never cleaned.

## What the Model Concluded

- Attributed the case to insider "Iaman Informant" (`informant`, `iaman.informant@nist.gov`) from seven sources, including the SID and password hint, the Outlook profile, the media labels, the resignation letter and a Google cookie, with no intrusion subplot and the three extra accounts correctly read as IT setup.
- Reconstructed the full chain: the February 15 copy of the five named documents (all sizes) to RM1, the local staging directory on March 24, all 17 disguised copies on RM2 with types, sizes and four exact mappings, and the same 17 burned to the UDF disc across nine sessions and covered with three Windows sample photos, tied to the PC's D: drive artifacts.
- Recovered the complete search history (27 terms with hit counts), both cloud clients to the second on March 23, and the Eraser and CCleaner install-and-run sequence on March 25 with every timestamp matching the answer key.
- Named the network share with all eight directories and the V: mapping, but dated the first access a day early and never identified either SanDisk Cruzer Fit by serial, although the run retrieved them.
- Repeated the series' one persistent error, CCleaner credited with "successfully" destroying browser history, and dismissed the email correspondent's address as carving noise. No second false positive.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 123 (55 disk, 68 other) |
| Total tool calls | 630 |
| Findings | 24 (3 critical, 11 high, 4 medium, 0 low, 6 info), 2 hypotheses ruled out |
| Confirmed / Inference | 21 / 3 |
| False positives | 1 |
| Runtime | 79 minutes |
| Model | claude-opus-4-6 (extended thinking, effort max) |
| Tokens | 56K uncached input / 240K output (prompt-cache reads not counted) |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (691 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,403 lines) |
| `mulder.log` | MCP server tool execution log (233 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
