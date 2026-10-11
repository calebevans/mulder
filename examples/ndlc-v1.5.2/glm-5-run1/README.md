# NDLC on GLM-5, run 1 of 3 (Mulder v1.5.2)

Mulder's autonomous investigation of the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) using the open-weight model `bedrock/zai.glm-5` on Amazon Bedrock through Mulder's LiteLLM proxy, run on the v1.5.2 release image with the model's native reasoning and no per-model overrides. The same evidence, prompts, tools and scoring rubric as the [Claude Opus 4.6 run](../opus-4.6-run1/) in this directory.

> **Evidence:** PC disk image + 3 removable media (USB x2, CD-R). No memory dumps, no network capture.

## Accuracy

Scored against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) with the same 20 ground-truth items and standards as the Opus baseline. See [ACCURACY-REPORT.md](ACCURACY-REPORT.md) for the item-by-item comparison.

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 4 | 20% |
| PARTIAL | 11 | 55% |
| MISSED | 4 | 20% |
| FALSE POSITIVE | 5 | 25% |

**20% full match, 75% detection rate, 25% false positive rate.** One of three GLM-5 runs on this image; see [run 2](../glm-5-run2/) (25% / 75% / 20%) and [run 3](../glm-5-run3/) (20% / 90% / 10%). Two of the four misses (USB connection times, timezone) came from a harness bug in this release: registry queries with upper-case hive names failed (fixed after v1.5.2).

## What the Model Concluded

- Correctly framed the case as an insider leak by the `informant` account (`iaman.informant@nist.gov`): Secret Project data taken from the `\\10.11.11.128\secured_drive` share, staged on RM2 as 17 Office documents disguised under media, archive and text extensions, burned to the "IAMAN CD" across nine UDF sessions with folder renames and decoy photos, then Eraser and CCleaner on March 25 and the resignation letter the same afternoon.
- Enumerated all 17 masqueraded RM2 files with true types and sizes and matched them file for file to the disc's session history, but never read a file off the disc, named only one of the five Secret Project documents, and reported no USB serial, no search history, no February copy and no timezone.
- Misread embedded sample-document metadata (OMB and Library of Congress addresses) as "theft of federal government data", and built a persistence subplot from the setup-day admin accounts and the .NET service that Eraser's installer registered, attaching five containment actions to it.
- Dated Eraser and CCleaner executions to January and mid-March 2015 from ShimCache binary dates, before the OS was installed, and credited CCleaner with destroying traces the answer key says it never touched. Those, with the government-data claim and the persistence subplot, are the five false positives.
- Costs an order of magnitude more input tokens than any other model here (9.3M for one run), with no context compactions or turn continuations.

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 1 PC + 3 removable media (RM1 USB, RM2 USB, RM3 CD-R) |
| Evidence sources indexed | 92 (44 disk, 48 other) |
| Total tool calls | 513 |
| Findings | 20 (4 critical, 11 high, 4 medium, 0 low, 1 info), 1 hypothesis ruled out |
| Confirmed / Inference | 16 / 4 |
| False positives | 5 |
| Runtime | 60 minutes |
| Model | bedrock/zai.glm-5 (native reasoning) |
| Tokens | 9.29M input / 157K output (no prompt caching through the proxy) |
| Exit code | 0, all quality gates passed (narrative gate on the third attempt), 0 turn continuations |
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
| `ndlc.audit.jsonl` | Structured tool execution audit log (541 entries) |
| `orchestrator.log` | Agent phase transitions and reasoning (2,097 lines) |
| `mulder.log` | MCP server tool execution log (381 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against the published answer key |
