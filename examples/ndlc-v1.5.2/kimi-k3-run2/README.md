# NDLC on Kimi K3, run 2 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/us.moonshotai.kimi-k3` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 7 | 35% |
| PARTIAL | 9 | 45% |
| MISSED | 3 | 15% |
| FALSE POSITIVE | 4 | 20% |

**35% full match, 80% detection rate, 20% false positive rate.** The lowest detection of the three Kimi K3 runs on this image: the catalog phase read the OS edition, timezone and USB connection dates and none of them reached the report. See [run 1](../kimi-k3-run1/) and [run 3](../kimi-k3-run3/).

## What the Model Concluded

- Attributed the leak to the insider `informant` (`iaman.informant@nist.gov`) from six converging sources (account and SID, NIST and personal Gmail addresses, the "IAMAN $_@" and "IAMAN CD" volume labels, the password hint "IAMAN", the resignation-letter filename) and named all five Secret Project documents with sizes on the "Authorized USB" drive, dated to the February 15 copy.
- Reconstructed three physical exfiltration vectors: the RM1 exFAT stick with original filenames, 17 deleted files on RM2 FAT32 renamed with false media and archive extensions (all 17 typed by signature), and the same 17 burned to a 9-session UDF CD-R "IAMAN CD" with the sensitive sessions deleted behind three Windows sample photos, with the mastering folders correctly placed on the optical drive.
- Recovered the premeditation trail: 17 verbatim searches with hit counts, the `\\10.11.11.128\secured_drive` share with all eight directories and the V: mapping, Google Drive installed on March 23 with its sync databases deleted, and Eraser and CCleaner executed on March 25 at times matching the answer key to the second.
- Got the same two things wrong as every Kimi run: CCleaner credited with destroying evidence, and the three lab-setup accounts cast as backdoor persistence. New this run, it read the correspondent's address `spy.conspirator@nist.gov` as the suspect's own persona and asserted a March 24 copy onto RM1.
- Left its own registry reads in the run log: the catalog phase saw "Windows 7 Ultimate", "Eastern Standard Time" and a Cruzer Fit connection on March 23, and the report delivers none of them, calling the OS "Windows XP" in one finding, labelling every FAT timestamp UTC, and giving no USB serial or connection time.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 330 (65 disk, 265 other) |
| Total tool calls | 1,271 |
| Findings | 31 (5 critical, 13 high, 8 medium, 1 low, 4 info), 2 hypotheses ruled out |
| Confirmed / Inference | 29 / 2 |
| False positives | 4 |
| Runtime | 70 minutes |
| Model | bedrock/us.moonshotai.kimi-k3 (native reasoning) |
| Tokens | 180K output (LiteLLM does not report input tokens for this model) |
| Exit code | 0, all quality gates passed, 11 turn-limit continuations |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (1,326 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,981 lines) |
| `mulder.log` | MCP server tool execution log (2,096 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
