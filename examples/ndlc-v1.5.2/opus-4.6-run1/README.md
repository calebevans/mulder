# NDLC on Claude Opus 4.6, run 1 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using `claude-opus-4-6` directly through the Anthropic API with extended thinking, run on the v1.5.2 release image. This is one of three Opus runs, the reference for the open-weight models in this directory, which used the same evidence, prompts, tools and scoring rubric. The original v1.5.1 Opus run of this case is kept in [examples/ndlc](../../ndlc/).

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the earlier baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison, including a per-item table across all four v1.5.2 models.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 9 | 45% |
| PARTIAL | 10 | 50% |
| MISSED | 0 | 0% |
| FALSE POSITIVE | 2 | 10% |

**45% full match, 95% detection rate, 10% false positive rate.** See [run 2](../opus-4.6-run2/) (50% / 90% / 10%) and [run 3](../opus-4.6-run3/) (45% / 95% / 5%). Against the v1.5.1 baseline (60% / 90% / 5%) it gained the full masquerading inventory, the CD-R contents and the network share, and lost exact USB serials, connection times and the deletion window to PARTIAL. One of its two false positives came from a harness defect found by this run (issue #232): the RM1 executor asked for `tsk.masquerade` by name and received RM2's rows.

## What the Model Concluded

- Attributed the case to a single insider, "Iaman Informant" (`informant`, `iaman.informant@nist.gov`), on seven converging sources: the SAM account and password hint, the resignation letter and its XPS copy, the Outlook OST reference, the "IAMAN $_@" and "IAMAN CD" media labels, and a personal Gmail address. No intrusion, privilege escalation or lateral movement was claimed.
- Reconstructed the five-week timeline to the second: the five `[secret_project]_*` documents copied to the exFAT "Authorized USB" stick on February 15, browsing of `\\10.11.11.128\secured_drive` (mapped as V:, all eight directories), the March 23 opens of two share files, and the March 24 exfiltration to USB and CD-R.
- Found all 17 disguised copies on RM2's FAT32 partition with true types, sizes and four exact original-to-fake mappings (for example `a_gift_from_you.gif` is `[secret_project]_detailed_proposal.docx`, 35,226,880 bytes), and traced the same set onto the CD-R across 9 UDF sessions, including the rename to abbreviated folder names and the final deletion that left three Windows sample photos as decoys.
- Recovered the premeditation research verbatim with hit counts (27 search terms including "anti-forensic tools", "cd burning method", "security checkpoint cd-r" and "DLP DRM"), every Eraser and CCleaner install and execution timestamp on March 25, and named `spy.conspirator@nist.gov` as an Outlook contact, held at inference.
- Errors: CCleaner credited with clearing browser history and the Run key (it was launched, closed and uninstalled), and RM1 given RM2's FAT32 partition through the source-name collision above. USB serials and first-connection times were seen during the run but did not reach the report.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 133 (74 disk, 59 other) |
| Total tool calls | 596 |
| Findings | 23 (3 critical, 9 high, 5 medium, 0 low, 6 info) |
| Confirmed / Inference | 19 / 4 |
| False positives | 2 |
| Runtime | 68 minutes |
| Model | claude-opus-4-6 (extended thinking, effort max) |
| Tokens | 37K uncached input / 239K output (prompt-cache reads not counted) |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (654 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,294 lines) |
| `mulder.log` | MCP server tool execution log (246 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
