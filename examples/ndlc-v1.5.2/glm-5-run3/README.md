# NDLC on GLM-5, run 3 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/zai.glm-5` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning and no per-model overrides. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 4 | 20% |
| PARTIAL | 14 | 70% |
| MISSED | 2 | 10% |
| FALSE POSITIVE | 2 | 10% |

**20% full match, 90% detection rate, 10% false positive rate.** The highest detection and lowest false-positive rate of the three GLM-5 runs on this image; see [run 1](../glm-5-run1/) and [run 2](../glm-5-run2/).

## What the Model Concluded

- Insider theft by the `informant` account (`iaman.informant@nist.gov`): 17 Office documents renamed with media, archive and database extensions, staged on the second SanDisk Cruzer Fit USB on March 24 and burned to the "IAMAN CD" that evening in nine sessions, with only three Windows sample photos left visible in the final session.
- Premeditation from browser history: "how to leak a secret", "data leakage methods", "leaking confidential information", a SANS data-leakage whitepaper, anti-forensic techniques and data-recovery software, all before the staging.
- Both USB sticks identified by vendor, model and serial with their registry connection times, the `\\10.11.11.128\secured_drive` share named as the source, Google Drive and iCloud present but judged unused, the CD "the final destination".
- Anti-forensics read from ShimCache binary dates: Eraser "installed" in January and CCleaner "executed" in mid-March, before the OS existed, alongside the real Eraser run on March 25; and the three setup-day accounts read as "backup access vectors" and put in containment. Those are the run's two false positives. For the first time in the series a report does not claim CCleaner cleaned anything, because this run never learned CCleaner ran on March 25.
- Not found: the five Secret Project filenames, the February copy to RM1, the timezone (queried and never reported), RM2's label, the email correspondent.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 90 (48 disk, 42 other) |
| Total tool calls | 362 |
| Findings | 20 (2 critical, 12 high, 2 medium, 1 low, 3 info) |
| Confirmed / Inference | 14 / 6 |
| False positives | 2 |
| Runtime | 61 minutes |
| Model | bedrock/zai.glm-5 (native reasoning) |
| Tokens | 8.40M input / 143K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed (readiness on the second attempt), 0 turn continuations |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (390 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,955 lines) |
| `mulder.log` | MCP server tool execution log (325 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
