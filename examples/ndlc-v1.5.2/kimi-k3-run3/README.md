# NDLC on Kimi K3, run 3 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/us.moonshotai.kimi-k3` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 10 | 50% |
| PARTIAL | 8 | 40% |
| MISSED | 1 | 5% |
| FALSE POSITIVE | 4 | 20% |

**50% full match, 95% detection rate, 20% false positive rate.** The best of the three Kimi K3 runs on this image and the first run in the series to score FOUND on the network-share item; see [run 1](../kimi-k3-run1/) and [run 2](../kimi-k3-run2/) for the spread.

## What the Model Concluded

- Attributed the case to insider "Iaman Informant" (account `informant`, `iaman.informant@nist.gov`, a personal Gmail, the password hint "IAMAN" and the resignation letter) on `informant-PC`, and explicitly ruled out an external actor.
- Reconstructed a four-day operation from March 22 to 25: premeditation searches ("how to leak a secret", "anti-forensic tools", "CD burning method", "DLP DRM"), Google Drive and iCloud installed on March 23, the `\\10.11.11.128\secured_drive` share browsed and two files opened, then on March 24 both SanDisk Cruzer Fit sticks by serial, 17 Office documents disguised as media files on RM2 "IAMAN $_@", and the "IAMAN CD" burned in 9 UDF sessions with only three stock photos left visible.
- Named all five Secret Project documents on RM1 "Authorized USB", typed all 17 masqueraded files on RM2 and on the disc, and extracted the disc's files to read their Office metadata.
- Dated Eraser and CCleaner to the second on March 25 and the Google Drive launch after them, but read CCleaner as trace cleaning, a .NET-installer `wevtutil` prefetch as event-log clearing, and three setup-day accounts as backdoors. Those, plus a dated March 24 copy onto RM1, are the four false positives.
- Missed the February 15 bulk copy entirely, never parsed the OST for the email correspondent, and labelled RM2's FAT-local timestamps as UTC.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 117 (43 disk, 74 other) |
| Total tool calls | 1,063 |
| Findings | 21 (2 critical, 11 high, 6 medium, 0 low, 2 info), 1 hypothesis ruled out |
| Confirmed / Inference | 21 / 0 |
| False positives | 4 |
| Runtime | 60 minutes |
| Model | bedrock/us.moonshotai.kimi-k3 (native reasoning) |
| Tokens | 170K output (LiteLLM does not report input tokens for this model) |
| Exit code | 0, all quality gates passed |
| Mulder | v1.5.2 |

## How It Was Run

Kimi K3 is absent from LiteLLM's model map, so its context window, output cap and reasoning support are supplied explicitly (see [Models LiteLLM does not know](../../../docs/usage-guide.md#models-litellm-does-not-know)):

```bash
docker run --privileged \
  -v /evidence:/evidence:ro -v cases:/home/mulder/.mulder/cases \
  -e AWS_REGION=us-west-2 \
  -e MULDER_MODEL_CONTEXT_WINDOW=262144 \
  -e MULDER_MODEL_MAX_OUTPUT_TOKENS=32768 \
  -e MULDER_MODEL_REASONING=1 \
  ghcr.io/calebevans/mulder:1.5.2 \
  mulder investigate /evidence ndlc --model bedrock/us.moonshotai.kimi-k3 --show-cli-stderr
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (1,116 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,465 lines) |
| `mulder.log` | MCP server tool execution log (1,225 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
