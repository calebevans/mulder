# NDLC on GLM-5, run 2 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/zai.glm-5` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning and no per-model overrides. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 5 | 25% |
| PARTIAL | 10 | 50% |
| MISSED | 4 | 20% |
| FALSE POSITIVE | 4 | 20% |

**25% full match, 75% detection rate, 20% false positive rate.** The best of the three GLM-5 runs on this image; see [run 1](../glm-5-run1/) and [run 3](../glm-5-run3/) for the spread.

## What the Model Concluded

- Named Iaman Informant (`informant`, `iaman.informant@nist.gov`) as an insider, "not an external attack", who opened the Secret Project files from the "Authorized USB" on March 23, wrote 17 Office documents disguised as media files to the "IAMAN $_@" USB on March 24, burned the same set to the "IAMAN CD" in nine sessions that evening, and ran Eraser and CCleaner before saving a resignation letter on March 25.
- Got the reconstruction right where it looked: all five Secret Project documents by name on RM1, all 17 masqueraded files with true types and sizes matched to the disc, the March 23 Google Drive install and the March 25 timeline exact, RM1's first connection exact, and its counter-analysis correctly rejected ShimCache binary dates as executions.
- Built the same wrong narrative on top as run 1: sample-document metadata became "theft of US Government documents" with "national security implications", the setup-day admin accounts became "the primary persistence mechanism" with a containment action to disable them, and the volume root's Windows 7 media timestamp became a timestomping phase. CCleaner is credited with cleaning, as in every run of every model. Those are the four false positives.
- Never read the search-history source, the ShellBags, the OST, the disc's files or an RM1 timeline, so it missed the February copy, the network share, the RM2 file opens and the timezone, and dropped the email correspondent after finding the address during the run.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 96 (47 disk, 49 other) |
| Total tool calls | 454 |
| Findings | 22 (6 critical, 10 high, 4 medium, 0 low, 2 info) |
| Confirmed / Inference | 19 / 3 |
| False positives | 4 |
| Runtime | 63 minutes |
| Model | bedrock/zai.glm-5 (native reasoning) |
| Tokens | 9.05M input / 135K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed on the first attempt, 0 turn continuations |
| Mulder | v1.5.2 |

## How It Was Run

GLM-5 is in LiteLLM's model map (200K context, reasoning), so no per-model overrides were needed:

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e AWS_REGION=us-west-2 \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model bedrock/zai.glm-5 --show-cli-stderr
```

Bedrock credentials came from the EC2 instance role.

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
| `ndlc.audit.jsonl` | Structured tool execution audit log (487 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,309 lines) |
| `mulder.log` | MCP server tool execution log (405 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
